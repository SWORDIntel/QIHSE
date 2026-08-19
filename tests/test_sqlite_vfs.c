#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main() {
    test_vfs_register();
    test_basic_create_open();
    test_write_read_pages();
    printf("All basic VFS tests passed!\n");
    return 0;
}
