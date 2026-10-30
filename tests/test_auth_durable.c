#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth.h"
#include "qihse_auth_maintenance.h"
#include "core/qihse_audit.h"
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Export executable symbols (-Wl,--export-dynamic -ldl). Linker --wrap cannot
 * intercept libqihse.so's I/O. Unarmed calls perform actual system I/O.
 * Every auth case execs: no inherited auth state, locks or audit threads. */
#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "durable test: %s:%d: %s\n", __FILE__, __LINE__, #x); \
    exit(1); } } while (0)
#define ROOT_PASSWORD "FixtureRoot-Initial42!"
#define ROOT_ROTATED "FixtureRoot-Rotated73!"
#define USER_PASSWORD "FixtureUser-Initial42!"
#define USER_ROTATED "FixtureUser-Rotated73!"
#define CRASH_EXIT 86
static _Atomic(const char *) fault;
static atomic_bool state_renamed, fault_hit;
static char executable[PATH_MAX], key_paths[4][PATH_MAX];
static void run(const char *dir, const char *action, int expected_exit);

static void join(char out[PATH_MAX], const char *dir, const char *name) {
    int n = snprintf(out, PATH_MAX, "%s/%s", dir, name);
    CHECK(n > 0 && n < PATH_MAX);
}
static bool is_fault(const char *name) {
    const char *armed = fault;
    return armed && !strcmp(armed, name);
}
static bool pending_fd(int fd) {
    char proc[64], target[PATH_MAX];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc, target, sizeof(target) - 1);
    if (n < 0) return false;
    target[n] = 0;
    return strstr(target, "/authority.pending.") != NULL;
}
ssize_t write(int fd, const void *buf, size_t size) {
    ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write) *(void **)(&real_write) = dlsym(RTLD_NEXT, "write");
    if (!real_write) _exit(125);
    if (fault && pending_fd(fd)) {
        if (is_fault("write")) { fault_hit = true; errno = EIO; return -1; }
        if (is_fault("short-write")) {
            if (atomic_exchange(&fault_hit, true)) { errno = EIO; return -1; }
            return real_write(fd, buf, size > 1 ? size / 2 : size);
        }
        if (is_fault("crash-after-write")) {
            ssize_t result = real_write(fd, buf, size);
            if (result > 0) _exit(CRASH_EXIT);
            return result;
        }
    }
    return real_write(fd, buf, size);
}
int fsync(int fd) {
    int (*real_fsync)(int) = NULL;
    struct stat st;
    if (!real_fsync) *(void **)(&real_fsync) = dlsym(RTLD_NEXT, "fsync");
    if (!real_fsync) _exit(125);
    bool pending = fault && pending_fd(fd);
    if (pending && is_fault("file-fsync")) { fault_hit = true; errno = EIO; return -1; }
    bool directory = state_renamed && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
    if (directory && is_fault("dir-fsync")) { fault_hit = true; errno = EIO; return -1; }
    int result = real_fsync(fd);
    if (!result && pending && is_fault("crash-before-rename")) _exit(CRASH_EXIT);
    if (!result && directory && is_fault("crash-after-dirsync")) _exit(CRASH_EXIT);
    return result;
}
int renameat(int olddir, const char *oldname, int newdir, const char *newname) {
    int (*real_renameat)(int, const char *, int, const char *) = NULL;
    if (!real_renameat) *(void **)(&real_renameat) = dlsym(RTLD_NEXT, "renameat");
    if (!real_renameat) _exit(125);
    bool state = fault && !strcmp(newname, "authority.state");
    if (state && is_fault("rename")) { fault_hit = true; errno = EIO; return -1; }
    int result = real_renameat(olddir, oldname, newdir, newname);
    if (!result && state) {
        state_renamed = true;
        if (is_fault("crash-after-rename")) _exit(CRASH_EXIT);
    }
    return result;
}
int renameat2(int olddir, const char *oldname, int newdir, const char *newname,
              unsigned int flags) {
    int (*real_renameat2)(int, const char *, int, const char *, unsigned int) = NULL;
    if (!real_renameat2) *(void **)(&real_renameat2) = dlsym(RTLD_NEXT, "renameat2");
    if (!real_renameat2) _exit(125);
    int result = real_renameat2(olddir, oldname, newdir, newname, flags);
    if (!result && is_fault("crash-bootstrap")) _exit(CRASH_EXIT);
    return result;
}
static void key_files(const char *dir) {
    const char *names[] = {"kem.pub", "kem.key", "dsa.key", "dsa.pub"};
    for (size_t i = 0; i < 4; ++i) join(key_paths[i], dir, names[i]);
}
static void pem_write(const char *path, EVP_PKEY *key, bool private_key) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600); CHECK(fd >= 0);
    FILE *f = fdopen(fd, "w"); CHECK(f);
    CHECK(private_key ? PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) == 1 :
                        PEM_write_PUBKEY(f, key) == 1);
    CHECK(fclose(f) == 0);
}
static void generate_pair(const char *algorithm, const char *public_file,
                          const char *private_file) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithm, NULL);
    EVP_PKEY *key = NULL;
    CHECK(ctx && EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_generate(ctx, &key) == 1);
    pem_write(public_file, key, false); pem_write(private_file, key, true);
    EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx);
}
static void pin(const char *path, uint8_t out[48]) {
    FILE *f = fopen(path, "r"); CHECK(f);
    EVP_PKEY *key = PEM_read_PUBKEY(f, NULL, NULL, NULL); CHECK(key);
    CHECK(fclose(f) == 0);
    unsigned char *der = NULL;
    int n = i2d_PUBKEY(key, &der); CHECK(n > 0);
    CHECK(SHA384(der, (size_t)n, out));
    OPENSSL_free(der); EVP_PKEY_free(key);
}
static qihse_auth_startup_config_t configuration(const char *dir, bool provision) {
    static char state[PATH_MAX], bootstrap[PATH_MAX];
    qihse_auth_startup_config_t c = {0};
    join(state, dir, "state"); join(bootstrap, dir, "bootstrap"); key_files(dir);
    c.mode = QIHSE_AUTH_AUTHORITY_STANDALONE;
    c.action = provision ? QIHSE_AUTH_START_PROVISION : QIHSE_AUTH_START_RECOVER;
    c.state_directory = state; c.bootstrap_file = bootstrap;
    c.archive_keys.recipient_public_file = key_paths[0];
    c.archive_keys.recipient_private_file = key_paths[1];
    c.archive_keys.signer_private_file = key_paths[2];
    c.archive_keys.signer_public_file = key_paths[3];
    pin(key_paths[0], c.archive_keys.recipient_pin);
    pin(key_paths[3], c.archive_keys.signer_pin);
    c.transfer_keys = c.archive_keys;
    memset(c.authority_id, 0x11, 16); memset(c.node, 0x22, 16);
    memset(c.expected_history, 0x33, 16); c.epoch = 7;
    c.minimum_generation = provision ? 0 : 1;
    return c;
}
static qihse_user_t *root_with_token(void) {
    qihse_user_t *root = qihse_auth_get_user(0); CHECK(root);
    CHECK(qihse_user_requires_hardware_token(root));
    CHECK(!qihse_user_has_hardware_token(root));
    CHECK(!qihse_auth_can_access(root, 1, 0));
    qihse_auth_maintenance_caps_t caps;
    CHECK(qihse_auth_maintenance_capabilities(root, &caps) == QIHSE_AUTH_MAINT_DENIED);
    CHECK(qihse_auth_set_hardware_token(root, true, NULL));
    CHECK(qihse_auth_can_access(root, 1, 0));
    CHECK(qihse_auth_maintenance_capabilities(root, &caps) == QIHSE_AUTH_MAINT_OK);
    CHECK(caps.ready && caps.mode == QIHSE_AUTH_AUTHORITY_STANDALONE);
    CHECK(caps.position.generation > 0 && caps.position.epoch == 7);
    for (size_t i = 0; i < 16; ++i) CHECK(caps.position.history[i] == 0x33);
    return root;
}
static void denied_actor(const qihse_user_t *actor) {
    qihse_auth_maintenance_caps_t caps;
    qihse_auth_position_t expected = {0}, result;
    qihse_auth_sealed_t *sealed = NULL;
    CHECK(qihse_auth_maintenance_capabilities(actor, &caps) == QIHSE_AUTH_MAINT_DENIED);
    CHECK(qihse_auth_maintenance_checkpoint(actor, &expected, &result) == QIHSE_AUTH_MAINT_DENIED);
    CHECK(qihse_auth_maintenance_export(actor, &expected, NULL, &sealed) == QIHSE_AUTH_MAINT_DENIED);
    CHECK(!sealed);
    CHECK(!qihse_auth_create_user(actor, 90, QIHSE_ROLE_OPERATOR, 0, 0, USER_PASSWORD, true));
    CHECK(!qihse_auth_modify_user(actor, 0, NULL, USER_PASSWORD, 0, 1, -1, -1));
}
static void mutate_all(qihse_user_t *root) {
    qihse_user_t *u = qihse_auth_create_user(root, 10, QIHSE_ROLE_ANALYST, 3, 1,
                                            USER_PASSWORD, true); CHECK(u);
    CHECK(qihse_auth_modify_user(root, 10, "durable-analyst", USER_ROTATED, 1, 1, 5, 3));
    CHECK(!qihse_auth_user_is_active(u));
    u = qihse_auth_get_user(10); CHECK(u);
    CHECK(qihse_auth_set_hardware_token(u, true, "fixture-analyst-token"));
    CHECK(!qihse_auth_user_is_active(u));
    u = qihse_auth_get_user(10); CHECK(u);
    CHECK(qihse_auth_grant_object(root, u, 7, 100, QIHSE_ACL_READ | QIHSE_ACL_WRITE));
    u = qihse_auth_get_user(10); CHECK(u);
    CHECK(qihse_auth_grant_object(root, u, 7, 101, QIHSE_ACL_READ));
    u = qihse_auth_get_user(10); CHECK(u);
    CHECK(qihse_auth_revoke_object(root, u, 7, 101));
    u = qihse_auth_get_user(10); CHECK(u);
    CHECK(!qihse_auth_can_access_object(u, 7, 101, QIHSE_ACL_READ));
    CHECK(!qihse_auth_create_user(u, 91, QIHSE_ROLE_OPERATOR, 0, 0, USER_PASSWORD, true));
    CHECK(qihse_auth_create_user(u, 11, QIHSE_ROLE_ANALYST, 4, 1, USER_PASSWORD, true));
    CHECK(qihse_auth_create_user(root, 12, QIHSE_ROLE_GUEST, 0, 0, USER_PASSWORD, true));
    CHECK(qihse_auth_create_tenant_user(root, 42, 13, QIHSE_ROLE_OPERATOR, 0, 0,
                                       USER_PASSWORD, true));
    CHECK(qihse_auth_create_user(root, 14, QIHSE_ROLE_ANALYST, 1, 0, USER_PASSWORD, true));
    uint64_t generation;
    qihse_user_t *old = qihse_auth_borrow_principal_scoped(14, &generation); CHECK(old);
    CHECK(qihse_auth_destroy_user(root, 14));
    CHECK(!qihse_auth_user_is_active(old)); denied_actor(old);
    CHECK(!qihse_auth_create_user(root, 14, QIHSE_ROLE_GUEST, 0, 0, USER_ROTATED, true));
    CHECK(!qihse_auth_validate_handle_generation(old, generation));
    qihse_auth_release_principal_scoped(old);
    CHECK(qihse_auth_create_user(root, 15, QIHSE_ROLE_GUEST, 0, 0, USER_PASSWORD, true));
    CHECK(qihse_auth_destroy_user(root, 15));
    CHECK(qihse_auth_create_user(root, 16, QIHSE_ROLE_ANALYST, 1, 0, USER_PASSWORD, true));
    /* Distinct IPs avoid mistaking local IP throttling for principal lockout.
     * Leave four failures to cross the exec boundary. */
    for (unsigned i = 0; i < 4; ++i)
        CHECK(!qihse_auth_authenticate_id_from(100 + i, 16, "wrong"));
    CHECK(qihse_auth_create_user(root, 17, QIHSE_ROLE_ANALYST, 1, 0, USER_PASSWORD, true));
    for (unsigned i = 0; i < 5; ++i)
        CHECK(!qihse_auth_authenticate_id_from(200 + i, 17, "wrong"));
    CHECK(!qihse_auth_authenticate_id_from(300, 17, USER_PASSWORD));
    CHECK(qihse_auth_modify_user(root, 0, "durable-root", ROOT_ROTATED, 1, 0, -1, -1));
    CHECK(!qihse_auth_user_is_active(root)); denied_actor(root);
    root = qihse_auth_get_user(0); CHECK(root);
    CHECK(qihse_auth_set_hardware_token(root, true, "fixture-root-rotated-token"));
    root = qihse_auth_get_user(0); CHECK(root);
    CHECK(qihse_auth_grant_object(root, root, 9, 900, QIHSE_ACL_READ));
}
static void verify_all(qihse_user_t *root) {
    CHECK(!strcmp(qihse_user_get_username(root), "durable-root"));
    CHECK(!strcmp(qihse_user_get_fido2_credential_id(root), "fixture-root-rotated-token"));
    CHECK(!qihse_user_can_create_users(root));
    CHECK(!qihse_auth_authenticate("fixture-root", ROOT_PASSWORD));
    CHECK(!qihse_auth_authenticate_id_from(401, 0, ROOT_PASSWORD));
    CHECK(qihse_auth_authenticate("durable-root", ROOT_ROTATED) == root);
    CHECK(qihse_auth_can_access_object(root, 9, 900, QIHSE_ACL_READ));
    qihse_user_t *u = qihse_auth_get_user(10); CHECK(u);
    CHECK(qihse_user_get_role(u) == QIHSE_ROLE_ANALYST);
    CHECK(qihse_user_get_classification(u) == 5 && qihse_user_get_sci(u) == 3);
    CHECK(qihse_user_can_create_users(u) && qihse_user_requires_hardware_token(u));
    CHECK(!qihse_user_has_hardware_token(u));
    CHECK(!strcmp(qihse_user_get_fido2_credential_id(u), "fixture-analyst-token"));
    CHECK(!qihse_auth_can_access(u, 1, 0));
    CHECK(!qihse_auth_authenticate("User_10", USER_PASSWORD));
    CHECK(!qihse_auth_authenticate_id_from(402, 10, USER_PASSWORD));
    CHECK(qihse_auth_authenticate("durable-analyst", USER_ROTATED) == u);
    CHECK(qihse_auth_set_hardware_token(u, true, NULL));
    CHECK(qihse_auth_can_access(u, 5, 3));
    CHECK(qihse_auth_create_user(u, 18, QIHSE_ROLE_GUEST, 0, 0, USER_PASSWORD, true));
    CHECK(!qihse_auth_can_access(u, 6, 0) && !qihse_auth_can_access(u, 5, 4));
    CHECK(qihse_auth_can_access_object(u, 7, 100, QIHSE_ACL_WRITE));
    CHECK(!qihse_auth_can_access_object(u, 7, 101, QIHSE_ACL_READ));
    CHECK(qihse_auth_authenticate_id(11, USER_PASSWORD));
    CHECK(qihse_user_get_role(qihse_auth_get_user(11)) == QIHSE_ROLE_GUEST);
    CHECK(!qihse_auth_get_user(15)); CHECK(!qihse_auth_authenticate_id(15, USER_PASSWORD));
    CHECK(!qihse_auth_get_user(14));
    CHECK(!qihse_auth_authenticate_id(14, USER_PASSWORD));
    CHECK(!qihse_auth_create_user(root, 14, QIHSE_ROLE_GUEST, 0, 0, USER_ROTATED, true));
    CHECK(!qihse_auth_create_user(root, 15, QIHSE_ROLE_GUEST, 0, 0, USER_ROTATED, true));
    CHECK(qihse_auth_create_user(root, 19, QIHSE_ROLE_GUEST, 0, 0, USER_ROTATED, true));
    CHECK(qihse_auth_get_user(16) && qihse_auth_get_user(17));
    CHECK(!qihse_auth_authenticate_id_from(403, 16, "wrong"));
    CHECK(!qihse_auth_authenticate_id_from(404, 16, USER_PASSWORD));
    CHECK(!qihse_auth_authenticate_id_from(405, 17, USER_PASSWORD));
    denied_actor(NULL);
    qihse_user_t *guest = qihse_auth_get_user(12); CHECK(guest);
    CHECK(qihse_auth_set_hardware_token(guest, true, NULL)); denied_actor(guest);
    qihse_user_t *tenant = qihse_auth_get_user(13); CHECK(tenant);
    CHECK(qihse_user_get_tenant_id(tenant) == 42);
    CHECK(qihse_auth_set_hardware_token(tenant, true, NULL)); denied_actor(tenant);
    CHECK(!qihse_auth_create_tenant_user(tenant, 43, 92, QIHSE_ROLE_GUEST, 0, 0,
                                         USER_PASSWORD, true));
    CHECK(!qihse_auth_create_user(tenant, 92, QIHSE_ROLE_GUEST, 0, 0, USER_PASSWORD, true));
    CHECK(!qihse_auth_can_access(NULL, 1, 0));
    CHECK(!qihse_auth_can_access(qihse_auth_get_user(12), 1, 0));
    qihse_auth_maintenance_caps_t caps;
    qihse_auth_position_t next;
    CHECK(qihse_auth_maintenance_capabilities(root, &caps) == QIHSE_AUTH_MAINT_OK);
    qihse_auth_position_t stale = caps.position; stale.generation--;
    CHECK(qihse_auth_maintenance_checkpoint(root, &stale, &next) == QIHSE_AUTH_MAINT_CONFLICT);
    CHECK(qihse_auth_maintenance_checkpoint(root, &caps.position, &next) == QIHSE_AUTH_MAINT_OK);
    CHECK(next.generation == caps.position.generation + 1);
}
static int child(const char *dir, const char *action) {
    char audit[PATH_MAX]; join(audit, dir, "audit");
    CHECK(setenv("QIHSE_DATA_DIR", audit, 1) == 0);
    CHECK(setenv("QIHSE_FIPS_MODE", "optional", 1) == 0);
    bool provision = !strcmp(action, "provision");
    qihse_auth_startup_config_t c = configuration(dir, provision);
    if (!strcmp(action, "bootstrap-crash")) {
        fault = "crash-bootstrap";
        (void)qihse_auth_bootstrap_provision(c.bootstrap_file, "fixture-root", ROOT_PASSWORD,
                                             true, "fixture-root-token", true);
        CHECK(false);
    }
    if (provision) {
        struct stat st;
        if (lstat(c.bootstrap_file, &st)) {
            CHECK(errno == ENOENT);
            CHECK(qihse_auth_bootstrap_provision(c.bootstrap_file, "fixture-root", ROOT_PASSWORD,
                true, "fixture-root-token", true) == QIHSE_AUTH_MAINT_OK);
        }
        CHECK(lstat(c.bootstrap_file, &st) == 0 && st.st_nlink == 1 && !(st.st_mode & 0077));
        CHECK(qihse_auth_bootstrap_provision(c.bootstrap_file, "replace-root", ROOT_ROTATED,
            true, "different-token", false) == QIHSE_AUTH_MAINT_CONFLICT);
        CHECK(lstat(c.bootstrap_file, &st) == 0 && st.st_nlink == 1);
    }
    bool reject = !strncmp(action, "reject-", 7);
    if (!strcmp(action, "reject-history")) c.expected_history[0] ^= 1;
    if (!strcmp(action, "reject-generation")) c.minimum_generation = UINT64_MAX;
    if (!strcmp(action, "reject-node")) c.node[0] ^= 1;
    if (!strcmp(action, "reject-authority")) c.authority_id[0] ^= 1;
    if (!strcmp(action, "reject-epoch")) c.epoch++;
    if (!strcmp(action, "reject-pin")) c.archive_keys.recipient_pin[0] ^= 1;
    if (!strcmp(action, "reject-signer-pin")) c.archive_keys.signer_pin[0] ^= 1;
    if (!strcmp(action, "reject-reprovision")) {
        c.action = QIHSE_AUTH_START_PROVISION; c.minimum_generation = 0;
    }
    if (!strcmp(action, "reject-key") || !strcmp(action, "reject-signer-key")) {
        size_t key_index = !strcmp(action, "reject-key") ? 1 : 3;
        int fd = open(key_paths[key_index], O_WRONLY | O_TRUNC | O_CLOEXEC); CHECK(fd >= 0);
        CHECK(write(fd, "invalid PEM\n", 12) == 12); CHECK(close(fd) == 0);
    }
    qihse_auth_recovery_t *recovery = NULL;
    qihse_auth_maintenance_status_t status = qihse_auth_maintenance_start(&c, &recovery);
    if (reject) {
        CHECK(status != QIHSE_AUTH_MAINT_OK && !recovery);
        CHECK(!qihse_auth_get_user(0));
        CHECK(!qihse_auth_authenticate_id(0, ROOT_PASSWORD));
        CHECK(!qihse_auth_authenticate_id(0, ROOT_ROTATED));
        CHECK(!qihse_auth_can_access(NULL, 1, 0));
        CHECK(!qihse_auth_bootstrap_operator(ROOT_PASSWORD));
    } else {
        CHECK(status == QIHSE_AUTH_MAINT_OK && recovery);
        qihse_auth_maintenance_recovery_release(recovery);
        qihse_user_t *root = root_with_token();
        if (provision) {
            CHECK(qihse_auth_authenticate("fixture-root", ROOT_PASSWORD) == root);
            run(dir, "reject-lock", 0);
        } else if (!strcmp(action, "mutate")) mutate_all(root);
        else if (!strcmp(action, "verify")) verify_all(root);
        else if (!strncmp(action, "fault-", 6)) {
            fault = action + 6;
            CHECK(!qihse_auth_create_user(root, 80, QIHSE_ROLE_ANALYST, 1, 0,
                                          USER_PASSWORD, true));
            fault = NULL;
            CHECK(fault_hit);
            CHECK(!qihse_auth_get_user(80)); CHECK(!qihse_auth_get_user(0));
            CHECK(!qihse_auth_authenticate_id(0, ROOT_PASSWORD));
            CHECK(!qihse_auth_create_user(root, 81, QIHSE_ROLE_GUEST, 0, 0,
                                          USER_PASSWORD, true));
        } else if (!strcmp(action, "present")) {
            CHECK(qihse_auth_authenticate_id(80, USER_PASSWORD));
        } else if (!strcmp(action, "absent")) {
            CHECK(!qihse_auth_get_user(80));
            CHECK(qihse_auth_create_user(root, 80, QIHSE_ROLE_ANALYST, 1, 0,
                                         USER_PASSWORD, true));
        } else CHECK(false);
    }
    qihse_auth_shutdown_rate_limiter(); qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown(); return 0;
}
static void run(const char *dir, const char *action, int expected_exit) {
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) {
        execl(executable, executable, "--child", dir, action, (char *)NULL);
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) CHECK(errno == EINTR);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected_exit) {
        fprintf(stderr, "durable test: child %s status %d (expected exit %d)\n",
                action, status, expected_exit); exit(1);
    }
}
static void copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY | O_CLOEXEC); CHECK(in >= 0);
    int out = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600); CHECK(out >= 0);
    unsigned char buf[8192]; ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) != 0) {
        if (n < 0) { CHECK(errno == EINTR); continue; }
        size_t offset = 0;
        while (offset < (size_t)n) {
            ssize_t wrote = write(out, buf + offset, (size_t)n - offset);
            if (wrote < 0 && errno == EINTR) continue;
            CHECK(wrote > 0); offset += (size_t)wrote;
        }
    }
    CHECK(close(in) == 0 && close(out) == 0);
}
static void fixture(const char *base, const char *name, char out[PATH_MAX]) {
    char path[PATH_MAX], src[PATH_MAX], dst[PATH_MAX];
    const char *keys[] = {"kem.pub", "kem.key", "dsa.key", "dsa.pub"};
    join(out, base, name); CHECK(mkdir(out, 0700) == 0);
    join(path, out, "state"); CHECK(mkdir(path, 0700) == 0);
    join(path, out, "audit"); CHECK(mkdir(path, 0700) == 0);
    for (size_t i = 0; i < 4; ++i) {
        join(src, base, keys[i]); join(dst, out, keys[i]); copy_file(src, dst);
    }
}
static void corrupt(const char *dir, const char *name) {
    char path[PATH_MAX]; join(path, dir, name);
    int fd = open(path, O_RDWR | O_CLOEXEC); CHECK(fd >= 0);
    struct stat st; CHECK(fstat(fd, &st) == 0 && st.st_size > 0);
    unsigned char b;
    CHECK(pread(fd, &b, 1, st.st_size - 1) == 1); b ^= 0x80;
    CHECK(pwrite(fd, &b, 1, st.st_size - 1) == 1);
    CHECK(fsync(fd) == 0 && close(fd) == 0);
}
static void remove_fixture(const char *path) {
    DIR *dir = opendir(path); CHECK(dir);
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char file[PATH_MAX]; join(file, path, entry->d_name);
        struct stat st; CHECK(lstat(file, &st) == 0);
        if (S_ISDIR(st.st_mode)) remove_fixture(file); else CHECK(unlink(file) == 0);
    }
    CHECK(closedir(dir) == 0 && rmdir(path) == 0);
}
int main(int argc, char **argv) {
    /* Native OpenSSL ML-KEM/ML-DSA required: no RSA substitution or skip. */
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, "default"); CHECK(provider);
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    CHECK(length > 0 && (size_t)length < sizeof(executable) - 1); executable[length] = 0;
    if (argc == 4 && !strcmp(argv[1], "--child")) {
        int result = child(argv[2], argv[3]); OSSL_PROVIDER_unload(provider); return result;
    }
    CHECK(argc == 1);
    const char *tmp = getenv("TMPDIR"); if (!tmp || !*tmp) tmp = "/tmp";
    char base[PATH_MAX], dir[PATH_MAX]; join(base, tmp, "qihse-auth-durable-XXXXXX");
    CHECK(mkdtemp(base)); CHECK(chmod(base, 0700) == 0);
    key_files(base);
    generate_pair("ML-KEM-1024", key_paths[0], key_paths[1]);
    generate_pair("ML-DSA-87", key_paths[3], key_paths[2]);
    fixture(base, "roundtrip", dir);
    run(dir, "provision", 0); run(dir, "mutate", 0); run(dir, "verify", 0);
    const char *rejections[] = {"reject-history", "reject-generation", "reject-node",
        "reject-authority", "reject-epoch", "reject-pin", "reject-signer-pin",
        "reject-reprovision", "reject-key", "reject-signer-key", "reject-state", "reject-bootstrap"};
    for (size_t i = 0; i < sizeof(rejections) / sizeof(rejections[0]); ++i) {
        fixture(base, rejections[i], dir); run(dir, "provision", 0);
        if (!strcmp(rejections[i], "reject-state")) corrupt(dir, "state/authority.state");
        if (!strcmp(rejections[i], "reject-bootstrap")) corrupt(dir, "bootstrap");
        run(dir, rejections[i], 0);
    }
    const char *faults[] = {"write", "short-write", "file-fsync", "rename", "dir-fsync",
        "crash-after-write", "crash-before-rename", "crash-after-rename", "crash-after-dirsync"};
    for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i) {
        fixture(base, faults[i], dir); run(dir, "provision", 0);
        char action[80]; CHECK(snprintf(action, sizeof(action), "fault-%s", faults[i]) > 0);
        bool crash = !strncmp(faults[i], "crash-", 6);
        run(dir, action, crash ? CRASH_EXIT : 0);
        bool published = !strcmp(faults[i], "dir-fsync") ||
                         !strcmp(faults[i], "crash-after-rename") ||
                         !strcmp(faults[i], "crash-after-dirsync");
        run(dir, published ? "present" : "absent", 0);
    }
    fixture(base, "bootstrap-crash", dir); run(dir, "bootstrap-crash", CRASH_EXIT);
    char bootstrap[PATH_MAX]; struct stat st; join(bootstrap, dir, "bootstrap");
    CHECK(lstat(bootstrap, &st) == 0 && st.st_nlink == 1);
    DIR *published = opendir(dir); CHECK(published);
    struct dirent *entry;
    while ((entry = readdir(published))) {
        if (strncmp(entry->d_name, ".bootstrap.", 11)) continue;
        char pending[PATH_MAX]; join(pending, dir, entry->d_name);
        CHECK(lstat(pending, &st) == 0 && st.st_nlink == 1);
    }
    CHECK(closedir(published) == 0);
    run(dir, "provision", 0);
    remove_fixture(base); OSSL_PROVIDER_unload(provider);
    puts("PASS: durable principals, recovery denial, real I/O failures and crash boundaries");
    return 0;
}
