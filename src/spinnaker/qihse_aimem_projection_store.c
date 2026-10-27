#include "qihse_aimem_projection_store.h"
#include <sqlite3.h>
#include <openssl/sha.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct qihse_aimem_projection_store {
    sqlite3* db;
    uint8_t model[32];
    size_t dim;
    uint32_t tenant, owner;
    size_t pending;
    uint64_t max_source_seq;
    bool building, failed;
};

static bool exec_sql(sqlite3* db, const char* sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}
static bool bounded_pages(sqlite3* db) {
    sqlite3_stmt* st = NULL;
    bool ok = sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) <= 4096;
    sqlite3_finalize(st);
    return ok;
}
static bool uuid_valid(const char* id) {
    if (!id || strnlen(id, 38) != 36) return false;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (id[i] != '-') return false; }
        else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f') ||
                   (id[i] >= 'A' && id[i] <= 'F'))) return false;
    }
    return true;
}
static bool digest_valid(const char* h) {
    if (!h || strnlen(h, 66) != 64) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f'))) return false;
    return true;
}
static bool scope_valid(const char* s) { return s && strnlen(s, 64) < 64; }
static bool safe_file(int dir, const char* name) {
    struct stat st;
    if (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) < 0) return errno == ENOENT;
    return S_ISREG(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 0777) == 0600 && st.st_nlink == 1 && st.st_size <= 128 * 1024 * 1024;
}
/* SQLite creates a rollback journal beside the DB. Keep both under an
 * exclusively owned directory; reject pre-existing SQLite sidecar attacks. */
static bool safe_path(const char* path) {
    if (!path || !*path || strlen(path) >= PATH_MAX - 16) return false;
    const char* slash = strrchr(path, '/');
    if (!slash || !slash[1] || strcmp(slash + 1, ".") == 0 || strcmp(slash + 1, "..") == 0) return false;
    int dir = open(path[0] == '/' ? "/" : ".",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return false;
    const char* p = path + (path[0] == '/');
    while (p < slash) {
        const char* end = memchr(p, '/', (size_t)(slash - p));
        if (!end) end = slash;
        size_t len = (size_t)(end - p);
        if (len && (len > NAME_MAX || (len == 2 && memcmp(p, "..", 2) == 0))) {
            close(dir); return false;
        }
        if (len && !(len == 1 && *p == '.')) {
            char component[NAME_MAX + 1];
            memcpy(component, p, len); component[len] = 0;
            int next = openat(dir, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            close(dir);
            if (next < 0) return false;
            dir = next;
        }
        p = end + (end < slash);
    }
    struct stat st;
    bool ok = fstat(dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 0777) == 0700 && safe_file(dir, slash + 1);
    const char* suffixes[] = { "-journal", "-wal", "-shm" };
    char side[PATH_MAX];
    for (size_t i = 0; ok && i < 3; ++i) {
        if (snprintf(side, sizeof(side), "%s%s", slash + 1, suffixes[i]) >= (int)sizeof(side) ||
            !safe_file(dir, side)) ok = false;
    }
    if (ok) {
        int fd = openat(dir, slash + 1, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
            (st.st_mode & 0777) != 0600 || st.st_nlink != 1) ok = false;
        if (fd >= 0) close(fd);
    }
    close(dir);
    return ok;
}
/* Version zero is accepted only for a newly created empty database. Never
 * interpret an older prototype's columns using the current row layout. */
static bool schema_compatible(sqlite3* db) {
    sqlite3_stmt* st = NULL;
    bool ok = sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &st, NULL) == SQLITE_OK;
    int version = -1;
    if (ok && sqlite3_step(st) == SQLITE_ROW) version = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    if (version == 1) return true;
    if (version != 0) return false;
    ok = sqlite3_prepare_v2(db,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_step(st) == SQLITE_ROW && sqlite3_column_int(st, 0) == 0;
    sqlite3_finalize(st);
    return ok;
}

static bool identity(qihse_aimem_projection_store_t* s) {
    sqlite3_stmt* st = NULL;
    bool ok = sqlite3_prepare_v2(s->db, "SELECT tenant,owner,model,dim FROM identity", -1, &st, NULL) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR;
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        st = NULL;
        ok = sqlite3_prepare_v2(s->db, "INSERT INTO identity VALUES(?,?,?,?)", -1, &st, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_int64(st, 1, s->tenant);
            sqlite3_bind_int64(st, 2, s->owner);
            sqlite3_bind_blob(st, 3, s->model, 32, SQLITE_STATIC);
            sqlite3_bind_int64(st, 4, (sqlite3_int64)s->dim);
            ok = sqlite3_step(st) == SQLITE_DONE;
        }
    } else if (rc == SQLITE_ROW) {
        const void* model = sqlite3_column_blob(st, 2);
        ok = sqlite3_column_int64(st, 0) == s->tenant &&
            sqlite3_column_int64(st, 1) == s->owner &&
            sqlite3_column_bytes(st, 2) == 32 && model &&
            memcmp(model, s->model, 32) == 0 &&
            sqlite3_column_int64(st, 3) == (sqlite3_int64)s->dim &&
            sqlite3_step(st) == SQLITE_DONE;
    } else ok = false;
    sqlite3_finalize(st);
    return ok;
}
qihse_aimem_projection_store_t* qihse_aimem_projection_store_open(
    const char* path, uint32_t tenant, uint32_t owner, const uint8_t model[32], size_t dimension) {
    if (!model || !dimension || dimension > QIHSE_AIMEM_PROJECTION_MAX_DIM || !safe_path(path)) return NULL;
    qihse_aimem_projection_store_t* s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->dim = dimension; s->tenant = tenant; s->owner = owner;
    memcpy(s->model, model, 32);
    if (sqlite3_open_v2(path, &s->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
        SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, NULL) != SQLITE_OK ||
        !exec_sql(s->db, "PRAGMA journal_mode=DELETE") ||
        !exec_sql(s->db, "PRAGMA synchronous=FULL") ||
        !exec_sql(s->db, "PRAGMA secure_delete=ON") ||
        !exec_sql(s->db, "PRAGMA page_size=4096") ||
        !bounded_pages(s->db) ||
        !schema_compatible(s->db) ||
        !exec_sql(s->db, "PRAGMA max_page_count=32768") ||
        !exec_sql(s->db, "BEGIN IMMEDIATE") ||
        !exec_sql(s->db, "CREATE TABLE IF NOT EXISTS identity(tenant INTEGER NOT NULL,owner INTEGER NOT NULL,model BLOB NOT NULL,dim INTEGER NOT NULL);") ||
        !exec_sql(s->db, "CREATE TABLE IF NOT EXISTS generation(source_seq INTEGER NOT NULL,epoch INTEGER NOT NULL);") ||
        !exec_sql(s->db, "CREATE TABLE IF NOT EXISTS rows(id TEXT PRIMARY KEY,digest TEXT NOT NULL,seq INTEGER NOT NULL,classification INTEGER NOT NULL,sci INTEGER NOT NULL,tenant INTEGER NOT NULL,owner INTEGER NOT NULL,project TEXT NOT NULL,worktree TEXT NOT NULL,workstream TEXT NOT NULL,session TEXT NOT NULL,kind INTEGER NOT NULL,vector BLOB NOT NULL,checksum BLOB NOT NULL);") ||
        !exec_sql(s->db, "CREATE TABLE IF NOT EXISTS staging(id TEXT PRIMARY KEY,digest TEXT NOT NULL,seq INTEGER NOT NULL,classification INTEGER NOT NULL,sci INTEGER NOT NULL,tenant INTEGER NOT NULL,owner INTEGER NOT NULL,project TEXT NOT NULL,worktree TEXT NOT NULL,workstream TEXT NOT NULL,session TEXT NOT NULL,kind INTEGER NOT NULL,vector BLOB NOT NULL,checksum BLOB NOT NULL);") ||
        !identity(s) || !exec_sql(s->db, "PRAGMA user_version=1") ||
        !exec_sql(s->db, "COMMIT") || !safe_path(path)) {
        if (s->db) { exec_sql(s->db, "ROLLBACK"); sqlite3_close(s->db); }
        free(s); return NULL;
    }
    return s;
}
static bool decode(qihse_aimem_projection_store_t* s, sqlite3_stmt* st, int vec_col, int check_col, float* out) {
    const void* vec = sqlite3_column_blob(st, vec_col);
    const void* check = sqlite3_column_blob(st, check_col);
    if (!vec || !check || sqlite3_column_bytes(st, vec_col) != (int)(s->dim * sizeof(float)) ||
        sqlite3_column_bytes(st, check_col) != SHA256_DIGEST_LENGTH) return false;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(vec, s->dim * sizeof(float), hash);
    if (memcmp(hash, check, sizeof(hash))) return false;
    memcpy(out, vec, s->dim * sizeof(float));
    for (size_t i = 0; i < s->dim; ++i) if (!isfinite(out[i])) return false;
    return true;
}
bool qihse_aimem_projection_store_lookup(qihse_aimem_projection_store_t* s,
    const char* id, const char* digest, float* out) {
    if (!s || !out || !uuid_valid(id) || !digest_valid(digest)) return false;
    sqlite3_stmt* st = NULL;
    bool ok = sqlite3_prepare_v2(s->db,
        "SELECT vector,checksum FROM rows WHERE id=? AND digest=? AND tenant=?", -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, digest, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, s->tenant);
        float tmp[QIHSE_AIMEM_PROJECTION_MAX_DIM];
        ok = sqlite3_step(st) == SQLITE_ROW && decode(s, st, 0, 1, tmp);
        if (ok) memcpy(out, tmp, s->dim * sizeof(float));
    }
    sqlite3_finalize(st);
    return ok;
}
bool qihse_aimem_projection_store_begin_generation(qihse_aimem_projection_store_t* s) {
    if (!s || s->building || !exec_sql(s->db, "BEGIN IMMEDIATE")) return false;
    s->building = true; s->failed = false; s->pending = 0; s->max_source_seq = 0;
    if (!exec_sql(s->db, "DELETE FROM staging")) {
        qihse_aimem_projection_store_abort_generation(s);
        return false;
    }
    return true;
}
bool qihse_aimem_projection_store_put(qihse_aimem_projection_store_t* s,
    const qihse_aimem_projection_row_t* r, const float* vector) {
    if (!s || !s->building || s->failed) return false;
    if (!r || !vector || !uuid_valid(r->id) || !digest_valid(r->content_sha256) ||
        !scope_valid(r->project) || !r->project[0] ||
        !scope_valid(r->worktree) || !scope_valid(r->workstream) ||
        !scope_valid(r->session) || r->tenant != s->tenant ||
        r->source_seq > INT64_MAX || s->pending >= QIHSE_AIMEM_PROJECTION_MAX_ROWS) {
        s->failed = true; return false;
    }
    for (size_t i = 0; i < s->dim; ++i) if (!isfinite(vector[i])) { s->failed = true; return false; }
    uint8_t checksum[32];
    SHA256((const unsigned char*)vector, s->dim * sizeof(float), checksum);
    sqlite3_stmt* st = NULL;
    bool ok = sqlite3_prepare_v2(s->db, "INSERT INTO staging VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_text(st, 1, r->id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, r->content_sha256, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)r->source_seq);
        sqlite3_bind_int(st, 4, r->classification);
        sqlite3_bind_int(st, 5, r->sci_compartment);
        sqlite3_bind_int64(st, 6, r->tenant);
        sqlite3_bind_int64(st, 7, r->owner);
        sqlite3_bind_text(st, 8, r->project, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, r->worktree, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, r->workstream, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, r->session, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 12, r->kind);
        sqlite3_bind_blob(st, 13, vector, (int)(s->dim * sizeof(float)), SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 14, checksum, 32, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    if (ok) {
        ++s->pending;
        if (r->source_seq > s->max_source_seq) s->max_source_seq = r->source_seq;
    } else s->failed = true;
    return ok;
}
bool qihse_aimem_projection_store_commit_generation(qihse_aimem_projection_store_t* s,
    uint64_t source_seq, uint64_t epoch) {
    if (!s || !s->building) return false;
    if (s->failed || source_seq > INT64_MAX || epoch > INT64_MAX || source_seq < s->max_source_seq) {
        qihse_aimem_projection_store_abort_generation(s); return false;
    }
    sqlite3_stmt* st = NULL;
    bool ok = exec_sql(s->db, "DELETE FROM rows") &&
        exec_sql(s->db, "INSERT INTO rows SELECT * FROM staging") &&
        exec_sql(s->db, "DELETE FROM staging") &&
        exec_sql(s->db, "DELETE FROM generation") &&
        sqlite3_prepare_v2(s->db, "INSERT INTO generation VALUES(?,?)", -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)source_seq);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)epoch);
        ok = sqlite3_step(st) == SQLITE_DONE && exec_sql(s->db, "COMMIT");
    }
    sqlite3_finalize(st);
    if (!ok) { qihse_aimem_projection_store_abort_generation(s); return false; }
    s->building = false; s->pending = 0;
    return true;
}
void qihse_aimem_projection_store_abort_generation(qihse_aimem_projection_store_t* s) {
    if (!s || !s->building) return;
    exec_sql(s->db, "ROLLBACK");
    s->building = false; s->failed = false; s->pending = 0;
}
bool qihse_aimem_projection_store_iterate(qihse_aimem_projection_store_t* s,
    qihse_aimem_projection_visit_fn visit, void* ctx, uint64_t* seq, uint64_t* epoch) {
    if (!s || s->building || !visit || !seq || !epoch) return false;
    sqlite3_stmt* st = NULL;
    bool ok = sqlite3_prepare_v2(s->db, "SELECT source_seq,epoch FROM generation", -1, &st, NULL) == SQLITE_OK;
    uint64_t a = 0, b = 0;
    if (ok) {
        if (sqlite3_step(st) != SQLITE_ROW) ok = false;
        else { a = (uint64_t)sqlite3_column_int64(st, 0); b = (uint64_t)sqlite3_column_int64(st, 1); }
    }
    sqlite3_finalize(st);
    if (!ok) return false;
    ok = sqlite3_prepare_v2(s->db,
        "SELECT id,digest,seq,classification,sci,tenant,owner,project,worktree,workstream,session,kind,vector,checksum FROM rows ORDER BY id", -1, &st, NULL) == SQLITE_OK;
    size_t count = 0;
    int rc = SQLITE_DONE;
    while (ok && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (++count > QIHSE_AIMEM_PROJECTION_MAX_ROWS) { ok = false; break; }
        qihse_aimem_projection_row_t r = {0};
        char* fields[] = { r.id, r.content_sha256, r.project, r.worktree, r.workstream, r.session };
        const int cols[] = { 0, 1, 7, 8, 9, 10 };
        const size_t caps[] = { sizeof(r.id), sizeof(r.content_sha256), sizeof(r.project), sizeof(r.worktree), sizeof(r.workstream), sizeof(r.session) };
        for (size_t i = 0; i < 6; ++i) {
            const unsigned char* text = sqlite3_column_text(st, cols[i]);
            int len = sqlite3_column_bytes(st, cols[i]);
            if (!text || len < 0 || (size_t)len >= caps[i] || memchr(text, 0, (size_t)len)) { ok = false; break; }
            memcpy(fields[i], text, (size_t)len);
        }
        if (!ok) break;
        r.source_seq = (uint64_t)sqlite3_column_int64(st, 2);
        r.classification = (uint16_t)sqlite3_column_int(st, 3);
        r.sci_compartment = (uint16_t)sqlite3_column_int(st, 4);
        r.tenant = (uint32_t)sqlite3_column_int64(st, 5);
        r.owner = (uint32_t)sqlite3_column_int64(st, 6);
        r.kind = (uint32_t)sqlite3_column_int64(st, 11);
        float vec[QIHSE_AIMEM_PROJECTION_MAX_DIM];
        if (!uuid_valid(r.id) || !digest_valid(r.content_sha256) || !r.project[0] ||
            sqlite3_column_int64(st, 2) < 0 || r.source_seq > a ||
            sqlite3_column_int64(st, 3) < 0 || sqlite3_column_int64(st, 3) > UINT16_MAX ||
            sqlite3_column_int64(st, 4) < 0 || sqlite3_column_int64(st, 4) > UINT16_MAX ||
            sqlite3_column_int64(st, 5) != s->tenant ||
            sqlite3_column_int64(st, 6) < 0 || sqlite3_column_int64(st, 6) > UINT32_MAX ||
            sqlite3_column_int64(st, 11) < 0 || sqlite3_column_int64(st, 11) > UINT32_MAX ||
            !scope_valid(r.worktree) || !scope_valid(r.workstream) || !scope_valid(r.session) ||
            !decode(s, st, 12, 13, vec) || !visit(ctx, &r, vec, s->dim)) ok = false;
    }
    if (rc != SQLITE_DONE) ok = false;
    sqlite3_finalize(st);
    if (ok) { *seq = a; *epoch = b; }
    return ok;
}
void qihse_aimem_projection_store_close(qihse_aimem_projection_store_t* s) {
    if (!s) return;
    qihse_aimem_projection_store_abort_generation(s);
    sqlite3_close(s->db);
    free(s);
}
