#include "qihse_aimem_projection_store.h"
#include <sqlite3.h>
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool visit(void* ctx, const qihse_aimem_projection_row_t* row, const float* v, size_t n) {
    int* count = ctx;
    assert(n == 3 && v[0] == 1.0f && row->source_seq == 7 && row->classification == 2);
    ++*count;
    return true;
}
int main(void) {
    char dir[] = "./tests/projection-store-XXXXXX";
    assert(mkdtemp(dir));
    assert(chmod(dir, 0700) == 0);
    char path[256];
    assert(snprintf(path, sizeof(path), "%s/cache.db", dir) < (int)sizeof(path));
    uint8_t model[32] = {1}, other[32] = {2};
    float v[3] = {1, 2, 3}, out[3] = {0};
    qihse_aimem_projection_row_t row = {
        .id = "12345678-1234-1234-1234-123456789abc",
        .content_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .source_seq = 7, .classification = 2, .sci_compartment = 3,
        .tenant = 4, .owner = 50, .kind = 1, .project = "p", .worktree = "w", .workstream = "b", .session = "s"
    };
    qihse_aimem_projection_store_t* s = qihse_aimem_projection_store_open(path, 4, 5, model, 3);
    assert(s);
    assert(qihse_aimem_projection_store_begin_generation(s));
    assert(qihse_aimem_projection_store_put(s, &row, v));
    qihse_aimem_projection_store_abort_generation(s);
    assert(!qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, out));
    assert(qihse_aimem_projection_store_begin_generation(s));
    assert(qihse_aimem_projection_store_put(s, &row, v));
    assert(qihse_aimem_projection_store_commit_generation(s, 7, 1));
    assert(qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, out) && out[2] == 3);
    assert(!qihse_aimem_projection_store_lookup(s, row.id, "abcdef", out));
    int count = 0;
    uint64_t seq = 0, epoch = 0;
    assert(qihse_aimem_projection_store_iterate(s, visit, &count, &seq, &epoch));
    assert(count == 1 && seq == 7 && epoch == 1);
    assert(qihse_aimem_projection_store_begin_generation(s));
    char journal[272];
    assert(snprintf(journal, sizeof(journal), "%s-journal", path) < (int)sizeof(journal));
    struct stat js;
    assert(stat(journal, &js) == 0 && (js.st_mode & 0777) == 0600);
    assert(qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, out));
    assert(qihse_aimem_projection_store_put(s, &row, v));
    assert(!qihse_aimem_projection_store_commit_generation(s, 6, 2));
    assert(qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, out));
    assert(qihse_aimem_projection_store_begin_generation(s));
    assert(qihse_aimem_projection_store_put(s, &row, v));
    assert(!qihse_aimem_projection_store_put(s, &row, v));
    assert(!qihse_aimem_projection_store_commit_generation(s, 8, 2));
    assert(qihse_aimem_projection_store_begin_generation(s));
    v[0] = NAN;
    assert(!qihse_aimem_projection_store_put(s, &row, v));
    assert(!qihse_aimem_projection_store_commit_generation(s, 8, 2));
    v[0] = 1;
    assert(qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, out));
    assert(qihse_aimem_projection_store_begin_generation(s));
    for (size_t i = 0; i < QIHSE_AIMEM_PROJECTION_MAX_ROWS; i++) {
        assert(snprintf(row.id, sizeof row.id,
            "00000000-0000-0000-0000-%012zx", i) == 36);
        assert(qihse_aimem_projection_store_put(s, &row, v));
    }
    assert(snprintf(row.id, sizeof row.id,
        "00000000-0000-0000-0000-%012zx", (size_t)QIHSE_AIMEM_PROJECTION_MAX_ROWS) == 36);
    assert(!qihse_aimem_projection_store_put(s, &row, v));
    assert(!qihse_aimem_projection_store_commit_generation(s, 7, 2));
    strcpy(row.id, "12345678-1234-1234-1234-123456789abc");
    assert(qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, out));
    qihse_aimem_projection_store_close(s);
    assert(!qihse_aimem_projection_store_open(path, 4, 5, other, 3));
    assert(!qihse_aimem_projection_store_open(path, 4, 6, model, 3));
    assert(!qihse_aimem_projection_store_open(path, 4, 5, model, 4));
    s = qihse_aimem_projection_store_open(path, 4, 5, model, 3);
    assert(s && qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, out));
    qihse_aimem_projection_store_close(s);
    sqlite3* db;
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_exec(db, "UPDATE rows SET vector=x'0102030405060708090a0b0c'", NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
    s = qihse_aimem_projection_store_open(path, 4, 5, model, 3);
    assert(s && !qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, out));
    assert(!qihse_aimem_projection_store_iterate(s, visit, &count, &seq, &epoch));
    qihse_aimem_projection_store_close(s);
    assert(chmod(path, 0644) == 0);
    assert(!qihse_aimem_projection_store_open(path, 4, 5, model, 3));
    assert(chmod(path, 0600) == 0);
    unlink(path);
    assert(symlink("cache.db", path) == 0);
    assert(!qihse_aimem_projection_store_open(path, 4, 5, model, 3));
    unlink(path);
    assert(chmod(dir, 0755) == 0);
    assert(!qihse_aimem_projection_store_open(path, 4, 5, model, 3));
    assert(chmod(dir, 0700) == 0);
    char linkdir[256], linked_db[256];
    assert(snprintf(linkdir, sizeof(linkdir), "%s/link", dir) < (int)sizeof(linkdir));
    assert(symlink(".", linkdir) == 0);
    assert(snprintf(linked_db, sizeof(linked_db), "%s/link/cache.db", dir) < (int)sizeof(linked_db));
    assert(!qihse_aimem_projection_store_open(linked_db, 4, 5, model, 3));
    unlink(linkdir);
    assert(sqlite3_open(path, &db) == SQLITE_OK);
    assert(sqlite3_exec(db, "CREATE TABLE legacy(branch TEXT)", NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(db);
    assert(chmod(path, 0600) == 0);
    assert(!qihse_aimem_projection_store_open(path, 4, 5, model, 3));
    unlink(path);
    /* A full generation at the maximum dimension must fit the bounded
     * SQLite page budget, not merely the row-count check. */
    float wide[QIHSE_AIMEM_PROJECTION_MAX_DIM];
    for (size_t i = 0; i < QIHSE_AIMEM_PROJECTION_MAX_DIM; i++) wide[i] = 1.0f;
    s = qihse_aimem_projection_store_open(path, 4, 5, model, QIHSE_AIMEM_PROJECTION_MAX_DIM);
    assert(s && qihse_aimem_projection_store_begin_generation(s));
    for (size_t i = 0; i < QIHSE_AIMEM_PROJECTION_MAX_ROWS; i++) {
        assert(snprintf(row.id, sizeof row.id,
            "00000000-0000-0000-0000-%012zx", i) == 36);
        assert(qihse_aimem_projection_store_put(s, &row, wide));
    }
    assert(qihse_aimem_projection_store_commit_generation(s, 7, 1));
    assert(qihse_aimem_projection_store_begin_generation(s));
    for (size_t i = 0; i < QIHSE_AIMEM_PROJECTION_MAX_ROWS; i++) {
        assert(snprintf(row.id, sizeof row.id,
            "00000000-0000-0000-0000-%012zx", i) == 36);
        assert(qihse_aimem_projection_store_put(s, &row, wide));
    }
    assert(qihse_aimem_projection_store_commit_generation(s, 7, 2));
    qihse_aimem_projection_store_close(s);
    assert(stat(path, &js) == 0 && js.st_size <= 128 * 1024 * 1024);
    s = qihse_aimem_projection_store_open(path, 4, 5, model, QIHSE_AIMEM_PROJECTION_MAX_DIM);
    assert(s);
    float restored[QIHSE_AIMEM_PROJECTION_MAX_DIM];
    assert(qihse_aimem_projection_store_lookup(s, row.id, row.content_sha256, restored));
    assert(restored[0] == 1.0f && restored[QIHSE_AIMEM_PROJECTION_MAX_DIM - 1] == 1.0f);
    qihse_aimem_projection_store_close(s);
    unlink(path);
    rmdir(dir);
    puts("projection store tests passed");
    return 0;
}
