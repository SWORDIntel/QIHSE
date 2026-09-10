/*
 * tests/test_operator_mode.c — QIHSE operator-only mode tests
 *
 * Tests:
 *   1. qihse_auth_init() bootstraps operator with password_set=true
 *   2. Operator (user 0) is active with ROLE_OPERATOR
 *   3. qihse_auth_is_operator_password_default() returns false
 *   4. Operator has full classification + SCI access
 *   5. Operator can create users
 *   6. No other users exist in operator-only mode
 *   7. QIHSE_OPERATOR_PASSWORD env var still works if set
 *
 * Build: make tests/test_operator_mode
 * Run:   LD_LIBRARY_PATH=. ./tests/test_operator_mode
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_auth.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  [TEST] %s ... ", #name); \
    tests_run++; \
    name(); \
    printf("PASS\n"); \
    tests_passed++; \
} while(0)

static void test_operator_bootstrapped(void) {
    /* Unset env var to test default operator-only mode */
    unsetenv("QIHSE_OPERATOR_PASSWORD");
    assert(qihse_auth_init());

    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(op->user_id == 0);
    assert(op->role == QIHSE_ROLE_OPERATOR);
    (void)op;
}

static void test_password_is_set(void) {
    /* In operator-only mode, password_set should be true */
    assert(!qihse_auth_is_operator_password_default());
}

static void test_operator_has_full_access(void) {
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(op->classification_level == 0xFFFF);
    assert(op->sci_compartments == 0xFFFF);
    (void)op;
}

static void test_operator_can_create_users(void) {
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(op->can_create_users == true);
    (void)op;
}

static void test_operator_username(void) {
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(strcmp(op->username, "GODMODE_OP") == 0);
    (void)op;
}

static void test_no_other_users(void) {
    /* In operator-only mode, only user 0 should exist */
    for (uint32_t i = 1; i < 64; i++) {
        qihse_user_t* u = qihse_auth_get_user(i);
        assert(u == NULL);
        (void)u;
    }
}

static void test_env_var_password(void) {
    /* Setting QIHSE_OPERATOR_PASSWORD should still work */
    setenv("QIHSE_OPERATOR_PASSWORD", "TestOperatorPass123!", 1);
    assert(qihse_auth_init());

    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(!qihse_auth_is_operator_password_default());
    (void)op;

    /* Operator should authenticate with the set password */
    qihse_user_t* authed = qihse_auth_authenticate("GODMODE_OP", "TestOperatorPass123!");
    assert(authed != NULL);
    (void)authed;

    unsetenv("QIHSE_OPERATOR_PASSWORD");
}

static void test_reinit_clears_state(void) {
    /* Re-init should clear any existing users and re-bootstrap */
    assert(qihse_auth_init());
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(op->role == QIHSE_ROLE_OPERATOR);
    (void)op;
}

int main(void) {
    printf("======================================\n");
    printf("  QIHSE Operator-Only Mode Tests      \n");
    printf("======================================\n\n");

    TEST(test_operator_bootstrapped);
    TEST(test_password_is_set);
    TEST(test_operator_has_full_access);
    TEST(test_operator_can_create_users);
    TEST(test_operator_username);
    TEST(test_no_other_users);
    TEST(test_env_var_password);
    TEST(test_reinit_clears_state);

    printf("\n======================================\n");
    printf("  %d/%d tests passed\n", tests_passed, tests_run);
    printf("======================================\n");

    return tests_run == tests_passed ? 0 : 1;
}
