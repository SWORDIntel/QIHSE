#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <ftw.h>
#include <limits.h>
#include <errno.h>

extern int qihse_vfs_register(int make_default);
extern void qihse_vfs_unregister(void);

#define TEST_ASSERT(cond) \
    do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); exit(1); } } while (0)

static void test_vfs_register() {
    printf("test_vfs_register...\n");
    TEST_ASSERT(qihse_vfs_register(0) == SQLITE_OK);
    TEST_ASSERT(sqlite3_vfs_find("qihse") != NULL);
}

static void test_basic_create_open() {
    printf("test_basic_create_open...\n");
    sqlite3* db = NULL;
    char* err = NULL;

    TEST_ASSERT(sqlite3_open_v2("file:test_basic.db?vfs=qihse", &db,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI,
                                NULL) == SQLITE_OK);

    TEST_ASSERT(sqlite3_exec(db, "CREATE TABLE t (x INT, y TEXT);", NULL, NULL, &err) == SQLITE_OK);
    TEST_ASSERT(sqlite3_exec(db, "INSERT INTO t VALUES (1, 'hello'), (2, 'world');", NULL, NULL, &err) == SQLITE_OK);
    TEST_ASSERT(sqlite3_close(db) == SQLITE_OK);

    TEST_ASSERT(sqlite3_open_v2("file:test_basic.db?vfs=qihse", &db,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_URI,
                                NULL) == SQLITE_OK);
    
    int count = 0;
    sqlite3_stmt* stmt = NULL;
    TEST_ASSERT(sqlite3_prepare_v2(db, "SELECT * FROM t ORDER BY x;", -1, &stmt, NULL) == SQLITE_OK);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
        if (count == 1) {
            TEST_ASSERT(sqlite3_column_int(stmt, 0) == 1);
            TEST_ASSERT(strcmp((const char*)sqlite3_column_text(stmt, 1), "hello") == 0);
        }
    }
    TEST_ASSERT(count == 2);
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    /* Main-db readonly opens use unix locking; no .qlock should be needed. */
    TEST_ASSERT(remove("test_basic.db.qlock") == 0 || errno == ENOENT);
    TEST_ASSERT(sqlite3_open_v2("file:test_basic.db?vfs=qihse", &db,
                                SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
                                NULL) == SQLITE_OK);
    TEST_ASSERT(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM t;", -1, &stmt, NULL) == SQLITE_OK);
    TEST_ASSERT(sqlite3_step(stmt) == SQLITE_ROW);
    TEST_ASSERT(sqlite3_column_int(stmt, 0) == 2);
    TEST_ASSERT(sqlite3_finalize(stmt) == SQLITE_OK);
    TEST_ASSERT(sqlite3_close(db) == SQLITE_OK);
    TEST_ASSERT(access("test_basic.db.qlock", F_OK) != 0);

    remove("test_basic.db");
    remove("test_basic.db.qlock");
    system("rm -rf test_basic.db.d");
}

static void test_write_read_pages() {
    printf("test_write_read_pages...\n");
    sqlite3* db = NULL;
    char* err = NULL;
    
    remove("test_pages.db");
    remove("test_pages.db.qlock");
    system("rm -rf test_pages.db.d");

    TEST_ASSERT(sqlite3_open_v2("file:test_pages.db?vfs=qihse", &db,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI,
                                NULL) == SQLITE_OK);

    TEST_ASSERT(sqlite3_exec(db, "BEGIN;", NULL, NULL, &err) == SQLITE_OK);
    TEST_ASSERT(sqlite3_exec(db, "CREATE TABLE big (id INTEGER PRIMARY KEY, data TEXT);", NULL, NULL, &err) == SQLITE_OK);
    
    sqlite3_stmt* stmt = NULL;
    TEST_ASSERT(sqlite3_prepare_v2(db, "INSERT INTO big (data) VALUES (?);", -1, &stmt, NULL) == SQLITE_OK);
    
    char pad[2048];
    memset(pad, 'A', sizeof(pad) - 1);
    pad[sizeof(pad)-1] = '\0';
    
    for (int i = 0; i < 50; i++) {
        sqlite3_bind_text(stmt, 1, pad, -1, SQLITE_STATIC);
        TEST_ASSERT(sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    TEST_ASSERT(sqlite3_exec(db, "COMMIT;", NULL, NULL, &err) == SQLITE_OK);
    TEST_ASSERT(sqlite3_close(db) == SQLITE_OK);

    TEST_ASSERT(sqlite3_open_v2("file:test_pages.db?vfs=qihse", &db,
                                SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
                                NULL) == SQLITE_OK);
    
    int count = 0;
    TEST_ASSERT(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM big;", -1, &stmt, NULL) == SQLITE_OK);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    TEST_ASSERT(count == 50);
}

static int scalar(sqlite3* db, const char* sql) {
    sqlite3_stmt* stmt = NULL;
    TEST_ASSERT(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK);
    TEST_ASSERT(sqlite3_step(stmt) == SQLITE_ROW);
    int value = sqlite3_column_int(stmt, 0);
    TEST_ASSERT(sqlite3_finalize(stmt) == SQLITE_OK);
    return value;
}

static void exec_ok(sqlite3* db, const char* sql) {
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "SQL: %s: %s\n", sql, sqlite3_errmsg(db));
    TEST_ASSERT(rc == SQLITE_OK);
}

static sqlite3* wal_open(const char* name) {
    sqlite3* db = NULL;
    int rc = sqlite3_open_v2(name, &db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "open: %s\n", db ? sqlite3_errmsg(db) : "NULL");
    TEST_ASSERT(rc == SQLITE_OK);
    sqlite3_busy_timeout(db, 5000);
    return db;
}

static char wal_test_dir[] = "test_sqlite_wal_XXXXXX";
static char suite_test_dir[PATH_MAX];
static char suite_data_dir[PATH_MAX];
static char suite_original_dir[PATH_MAX];

static int remove_wal_fixture(const char* path, const struct stat* st,
                              int type, struct FTW* info) {
    (void)st; (void)type; (void)info;
    return remove(path);
}

static void cleanup_wal_fixture(void) {
    if (strchr(wal_test_dir, 'X') == NULL)
        nftw(wal_test_dir, remove_wal_fixture, 16, FTW_DEPTH | FTW_PHYS);
}

static void cleanup_suite_fixture(void) {
    if (suite_original_dir[0] && suite_test_dir[0] && chdir(suite_original_dir) == 0)
        nftw(suite_test_dir, remove_wal_fixture, 16, FTW_DEPTH | FTW_PHYS);
    if (suite_data_dir[0]) nftw(suite_data_dir, remove_wal_fixture, 16, FTW_DEPTH | FTW_PHYS);
}

static void test_wal_reopen_and_concurrent_handles(void) {
    printf("test_wal_reopen_and_concurrent_handles...\n");
    TEST_ASSERT(mkdtemp(wal_test_dir) != NULL);
    TEST_ASSERT(atexit(cleanup_wal_fixture) == 0);
    char name[256];
    TEST_ASSERT(snprintf(name, sizeof(name), "file:%s/test.db?vfs=qihse", wal_test_dir) < (int)sizeof(name));
    sqlite3* writer = wal_open(name);
    sqlite3_stmt* pragma = NULL;
    TEST_ASSERT(sqlite3_prepare_v2(writer, "PRAGMA journal_mode=WAL", -1,
                                   &pragma, NULL) == SQLITE_OK);
    TEST_ASSERT(sqlite3_step(pragma) == SQLITE_ROW);
    TEST_ASSERT(strcmp((const char*)sqlite3_column_text(pragma, 0), "wal") == 0);
    TEST_ASSERT(sqlite3_finalize(pragma) == SQLITE_OK);
    exec_ok(writer, "CREATE TABLE wal_test (id INTEGER PRIMARY KEY, val INTEGER)");
    exec_ok(writer, "INSERT INTO wal_test VALUES (1, 10)");
    sqlite3* readonly = NULL;
    TEST_ASSERT(sqlite3_open_v2(name, &readonly,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, NULL) == SQLITE_OK);
    TEST_ASSERT(scalar(readonly, "SELECT val FROM wal_test") == 10);
    TEST_ASSERT(sqlite3_close(readonly) == SQLITE_OK);
    sqlite3* reader = wal_open(name);
    TEST_ASSERT(scalar(reader, "SELECT val FROM wal_test") == 10);
    exec_ok(reader, "BEGIN");
    TEST_ASSERT(scalar(reader, "SELECT val FROM wal_test") == 10);
    exec_ok(writer, "UPDATE wal_test SET val=20");
    TEST_ASSERT(scalar(reader, "SELECT val FROM wal_test") == 10);
    exec_ok(reader, "COMMIT");
    TEST_ASSERT(scalar(reader, "SELECT val FROM wal_test") == 20);
    TEST_ASSERT(sqlite3_close(writer) == SQLITE_OK);
    TEST_ASSERT(sqlite3_close(reader) == SQLITE_OK);
    reader = wal_open(name);
    TEST_ASSERT(scalar(reader, "SELECT val FROM wal_test") == 20);
    exec_ok(reader, "PRAGMA wal_checkpoint(TRUNCATE)");
    TEST_ASSERT(sqlite3_close(reader) == SQLITE_OK);

    /* A process dying without xClose leaves WAL frames to recover. */
    pid_t child = fork();
    TEST_ASSERT(child >= 0);
    if (child == 0) {
        sqlite3* db = wal_open(name);
        exec_ok(db, "UPDATE wal_test SET val=30");
        _exit(0);
    }
    int status = 0;
    TEST_ASSERT(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    reader = wal_open(name);
    TEST_ASSERT(scalar(reader, "SELECT val FROM wal_test") == 30);
    TEST_ASSERT(sqlite3_close(reader) == SQLITE_OK);
}

int main() {
    char qdd[] = "build/test_sqlite_vfs_XXXXXX";
    TEST_ASSERT(mkdir("build", 0700) == 0 || errno == EEXIST);
    TEST_ASSERT(mkdtemp(qdd) != NULL);
    char data_dir[PATH_MAX];
    TEST_ASSERT(realpath(qdd, data_dir) != NULL);
    TEST_ASSERT(snprintf(suite_data_dir, sizeof(suite_data_dir), "%s", data_dir) < (int)sizeof(suite_data_dir));
    TEST_ASSERT(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    TEST_ASSERT(getcwd(suite_original_dir, sizeof(suite_original_dir)) != NULL);
    char root[] = "test_sqlite_vfs_files_XXXXXX";
    TEST_ASSERT(mkdtemp(root) != NULL);
    TEST_ASSERT(realpath(root, suite_test_dir) != NULL);
    TEST_ASSERT(atexit(cleanup_suite_fixture) == 0);
    TEST_ASSERT(chdir(suite_test_dir) == 0);
    test_vfs_register();
    test_basic_create_open();
    test_write_read_pages();
    test_wal_reopen_and_concurrent_handles();
    printf("All SQLite VFS tests passed!\n");
    return 0;
}
