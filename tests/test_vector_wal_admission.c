#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_container_keys_fixture.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "../persistence/qihse_container.h"
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned fail_allocation, allocation_count;
static bool allocation_failed, fail_wal_read, fail_wal_repair;
void* __real_malloc(size_t);
void* __real_calloc(size_t, size_t);
void* __real_realloc(void*, size_t);
static bool reject_allocation(void) {
    if (fail_allocation && ++allocation_count == fail_allocation) {
        allocation_failed = true;
        errno = ENOMEM;
        return true;
    }
    return false;
}
void* __wrap_malloc(size_t n) { return reject_allocation() ? NULL : __real_malloc(n); }
void* __wrap_calloc(size_t n, size_t z) { return reject_allocation() ? NULL : __real_calloc(n,z); }
void* __wrap_realloc(void* p, size_t n) { return reject_allocation() ? NULL : __real_realloc(p,n); }
bool __real_qihse_ctr_read_section_alloc(const qihse_container_t*, uint16_t, uint8_t**, size_t*);
bool __wrap_qihse_ctr_read_section_alloc(const qihse_container_t* ctr, uint16_t section,
                                        uint8_t** out, size_t* size) {
    if (fail_wal_read && section == QIHSE_CTR_SEC_WAL) {
        fail_wal_read = false;
        *out = NULL; *size = 0;
        errno = EIO;
        return false;
    }
    return __real_qihse_ctr_read_section_alloc(ctr, section, out, size);
}
bool __real_qihse_ctr_wal_truncate(qihse_container_t*, uint64_t);
bool __wrap_qihse_ctr_wal_truncate(qihse_container_t* ctr, uint64_t size) {
    if (fail_wal_repair) { fail_wal_repair = false; errno = EIO; return false; }
    return __real_qihse_ctr_wal_truncate(ctr, size);
}

static qihse_user_t* operator_user;
static qihse_vector_db_persistence_stats_t stats(qihse_vector_db_t db) {
    qihse_vector_db_persistence_stats_t s;
    assert(qihse_vector_db_get_persistence_stats(db, &s));
    return s;
}
static void expect_vector(qihse_vector_db_t db, uint64_t id, const float* expected, size_t dims) {
    float* got = calloc(dims, sizeof(*got)); assert(got);
    size_t actual_dims = 0;
    assert(qihse_vector_db_get_vector_by_id_user(db, operator_user, id, got, &actual_dims));
    assert(actual_dims == dims && memcmp(got, expected, dims * sizeof(*got)) == 0);
    free(got);
}
static void test_rejected_add_does_not_poison_wal(const char* path) {
    qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, path);
    assert(db);
    float v[3] = {1,2,3}; uint64_t id = 17;
    assert(qihse_vector_db_add_vectors(db,v,1,2,&id,NULL,NULL));
    assert(qihse_vector_db_flush(db));
    qihse_vector_db_persistence_stats_t before = stats(db);
    errno = 0;
    assert(!qihse_vector_db_add_vectors(db,v,1,2,&id,NULL,NULL) && errno == EEXIST);
    uint64_t other = 18;
    errno = 0;
    assert(!qihse_vector_db_add_vectors(db,v,1,3,&other,NULL,NULL) && errno == EINVAL);
    float batch[4] = {3,4,5,6}; uint64_t ids[2] = {18,17};
    assert(!qihse_vector_db_add_vectors(db,batch,2,2,ids,NULL,NULL));
    qihse_vector_db_persistence_stats_t after = stats(db);
    assert(before.wal_bytes_pending == after.wal_bytes_pending && after.live_vectors == 1);
    expect_vector(db,id,v,2);
    qihse_vector_db_destroy(db);
    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED);
    assert(db && stats(db).live_vectors == 1);
    expect_vector(db,id,v,2);
    qihse_vector_db_destroy(db);
}

static void test_allocation_failures_are_atomic(void) {
    float* vectors = calloc(2000, sizeof(float)); assert(vectors);
    const uint64_t ids[2] = {1,2};
    unsigned failures = 0;
    for (unsigned failure = 1; failure <= 8; failure++) {
        qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,NULL,NULL); assert(db);
        fail_allocation = failure; allocation_count = 0; allocation_failed = false;
        bool ok = qihse_vector_db_add_vectors(db,vectors,2,1000,ids,NULL,NULL);
        fail_allocation = 0;
        if (allocation_failed) {
            failures++;
            assert(!ok && stats(db).live_vectors == 0 && stats(db).vector_dims == 0);
            float retry[3] = {3,2,1};
            assert(qihse_vector_db_add_vectors(db,retry,1,3,ids,NULL,NULL));
            expect_vector(db,ids[0],retry,3);
        } else assert(ok && stats(db).live_vectors == 2);
        qihse_vector_db_destroy(db);
    }
    assert(failures >= 5);
    free(vectors);
    /* Grow an existing row/tracking allocation. A failed member of the
     * tracking group must not leave pointers invalid or destroy old rows. */
    for (unsigned failure = 1; failure <= 6; failure++) {
        qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,NULL,NULL); assert(db);
        float initial[8] = {1,2,3,4,5,6,7,8};
        uint64_t initial_ids[8] = {1,2,3,4,5,6,7,8};
        assert(qihse_vector_db_add_vectors(db,initial,8,1,initial_ids,NULL,NULL));
        float ninth = 9; uint64_t ninth_id = 9;
        fail_allocation = failure; allocation_count = 0; allocation_failed = false;
        bool ok = qihse_vector_db_add_vectors(db,&ninth,1,1,&ninth_id,NULL,NULL);
        fail_allocation = 0;
        if (allocation_failed) {
            assert(!ok && stats(db).live_vectors == 8);
            assert(qihse_vector_db_add_vectors(db,&ninth,1,1,&ninth_id,NULL,NULL));
        } else assert(ok);
        for (size_t i=0;i<8;i++) expect_vector(db,initial_ids[i],&initial[i],1);
        expect_vector(db,ninth_id,&ninth,1);
        qihse_vector_db_destroy(db);
    }
}

static uint8_t* wal_copy(const char* path, size_t* size) {
    qihse_container_t ctr; uint8_t* bytes = NULL;
    assert(qihse_ctr_open_read(path,&ctr));
    assert(__real_qihse_ctr_read_section_alloc(&ctr,QIHSE_CTR_SEC_WAL,&bytes,size));
    qihse_ctr_close(&ctr);
    return bytes;
}
static void expect_wal(const char* path, const uint8_t* expected, size_t size) {
    size_t got_size; uint8_t* got = wal_copy(path,&got_size);
    assert(got_size == size && memcmp(got,expected,size) == 0);
    free(got);
}
static void append_tail(const char* path, const uint8_t* tail, size_t size) {
    qihse_container_t ctr; assert(qihse_ctr_open_write(path,false,&ctr));
    assert(qihse_ctr_wal_append(&ctr,tail,size)); qihse_ctr_close(&ctr);
}
static void put64(uint8_t* p, uint64_t n) {
    for (unsigned i=0;i<8;i++) { p[i] = (uint8_t)n; n >>= 8; }
}
static void test_wal_read_and_repair_failures(const char* path) {
    float v[2] = {7,8}; uint64_t id = 42;
    qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,NULL,path); assert(db);
    assert(qihse_vector_db_add_vectors(db,v,1,2,&id,NULL,NULL));
    qihse_vector_db_destroy(db); /* committed WAL, no snapshot */
    size_t valid_size; uint8_t* valid = wal_copy(path,&valid_size);
    fail_wal_read = true; errno = 0;
    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED);
    assert(!db && !fail_wal_read && errno == EIO);
    expect_wal(path,valid,valid_size);

    const uint8_t tail[] = {0x45,0x52,0x52};
    append_tail(path,tail,sizeof(tail));
    size_t torn_size; uint8_t* torn = wal_copy(path,&torn_size);
    fail_wal_repair = true; errno = 0;
    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED);
    assert(!db && !fail_wal_repair && errno == EIO);
    expect_wal(path,torn,torn_size);
    free(torn);
    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED|QIHSE_VDB_OPEN_READ_ONLY);
    assert(db); expect_vector(db,id,v,2); qihse_vector_db_destroy(db);
    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED);
    assert(db); expect_wal(path,valid,valid_size); expect_vector(db,id,v,2);
    qihse_vector_db_destroy(db);
    /* Declared payload arithmetic must not wrap and reach the checksum
     * reader with SIZE_MAX bytes. This header follows a real commit. */
    uint8_t huge[64] = {0}; memcpy(huge,"QHWAL01",7);
    huge[8] = 1; huge[12] = 1;
    put64(huge+16,2); put64(huge+24,UINT64_MAX);
    put64(huge+40,valid_size-80u);
    append_tail(path,huge,sizeof(huge));
    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED);
    assert(db); expect_wal(path,valid,valid_size);
    uint64_t next = 43; assert(qihse_vector_db_add_vectors(db,v,1,2,&next,NULL,NULL));
    qihse_vector_db_destroy(db);
    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED);
    assert(db); expect_vector(db,id,v,2); expect_vector(db,next,v,2);
    qihse_vector_db_destroy(db);
    free(valid);
}
static int remove_entry(const char* path, const struct stat* s, int type, struct FTW* w) {
    (void)s; (void)type; (void)w; return remove(path);
}
int main(void) {
    char root[] = "tests/vector-wal-admission-XXXXXX"; assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR",root,1) == 0);
    assert(setenv("QIHSE_FIPS_MODE","disabled",1) == 0);
    qihse_test_container_keys(root);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("VectorAdmissionOperator123!"));
    operator_user = qihse_auth_get_user(0); assert(operator_user);
    char path[256]; snprintf(path,sizeof(path),"%s/admission.qdb",root);
    test_rejected_add_does_not_poison_wal(path);
    test_allocation_failures_are_atomic();
    snprintf(path,sizeof(path),"%s/recovery.qdb",root);
    test_wal_read_and_repair_failures(path);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    assert(nftw(root,remove_entry,16,FTW_DEPTH|FTW_PHYS) == 0);
    puts("PASS vector ADD admission, allocation atomicity, and WAL read/tail recovery faults");
    return 0;
}
