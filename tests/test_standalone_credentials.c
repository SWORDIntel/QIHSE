#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define QIHSE_STANDALONE_CREDENTIAL_TEST

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../tools/qihse_redis_server.c"

#define OPERATOR_PASSWORD "StandaloneOperatorPassword-2026"
#define SERVICE_PASSWORD "StandaloneAimemServicePassword-2026"

static bool all_zero(const void* value, size_t len) {
    const unsigned char* bytes = (const unsigned char*)value;
    for (size_t i = 0; i < len; i++) if (bytes[i] != 0u) return false;
    return true;
}

int main(void) {
    char data_dir[] = "/tmp/qihse-standalone-credentials-XXXXXX";
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_OPERATOR_PASSWORD", OPERATOR_PASSWORD, 1) == 0);
    assert(setenv("QIHSE_AIMEM_SERVICE_PASSWORD", SERVICE_PASSWORD, 1) == 0);
    assert(setenv("QIHSE_AUTH_PASSWORD", "obsolete-shared-password", 1) == 0);
    assert(setenv("QIHSE_AIMEM_SERVICE_USER_ID", "64991", 1) == 0);
    assert(setenv("QIHSE_AIMEM_SERVICE_TENANT_ID", "71", 1) == 0);

    standalone_credentials_t credentials;
    memset(&credentials, 0, sizeof(credentials));
    assert(standalone_secret_copy(credentials.operator_password,
                                  &credentials.operator_set,
                                  getenv("QIHSE_OPERATOR_PASSWORD")));
    assert(standalone_secret_copy(credentials.aimem_service_password,
                                  &credentials.aimem_service_set,
                                  getenv("QIHSE_AIMEM_SERVICE_PASSWORD")));

    char argv_secret[] = "argv-password-to-cleanse";
    char argv_copy[QIHSE_STANDALONE_SECRET_MAX] = {0};
    bool argv_set = false;
    assert(standalone_secret_take_argv(argv_copy, &argv_set, argv_secret));
    assert(argv_set);
    assert(strcmp(argv_copy, "argv-password-to-cleanse") == 0);
    assert(all_zero(argv_secret, sizeof(argv_secret) - 1u));
    OPENSSL_cleanse(argv_copy, sizeof(argv_copy));

    uint32_t user_id = 0u, tenant_id = 0u;
    assert(standalone_parse_nonzero_id("QIHSE_AIMEM_SERVICE_USER_ID", 1u,
                                      65535u,
                                      &user_id));
    assert(standalone_parse_nonzero_id("QIHSE_AIMEM_SERVICE_TENANT_ID", 1u,
                                      UINT32_MAX - 1u,
                                      &tenant_id));
    assert(user_id == 64991u);
    assert(tenant_id == 71u);

    assert(qihse_auth_init());
    qihse_user_t* startup_operator = qihse_auth_authenticate_id(
        0u, credentials.operator_password);
    assert(startup_operator);
    qihse_user_t* service = standalone_bootstrap_aimem_service(
        startup_operator, credentials.aimem_service_password, tenant_id, user_id);
    assert(service);
    assert(qihse_user_get_id(service) == user_id);
    assert(qihse_user_get_tenant_id(service) == tenant_id);
    assert(qihse_user_get_role(service) == QIHSE_ROLE_ANALYST);
    assert(qihse_user_get_classification(service) == UINT16_MAX);
    assert(qihse_user_get_sci(service) == UINT16_MAX);

    standalone_credentials_clear(&credentials);
    assert(all_zero(&credentials, sizeof(credentials)));
    assert(getenv("QIHSE_OPERATOR_PASSWORD") == NULL);
    assert(getenv("QIHSE_AUTH_PASSWORD") == NULL);
    assert(getenv("QIHSE_AIMEM_SERVICE_PASSWORD") == NULL);

    /* Verifiers remain usable after all plaintext sources are removed. */
    assert(qihse_auth_authenticate("GODMODE_OP", OPERATOR_PASSWORD));
    service = qihse_auth_authenticate("AIMEM_SERVICE", SERVICE_PASSWORD);
    assert(service);
    assert(qihse_user_get_role(service) != QIHSE_ROLE_OPERATOR);

    printf("standalone credential lifecycle tests passed\n");
    return 0;
}
