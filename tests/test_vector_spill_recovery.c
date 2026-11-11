#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_container_keys_fixture.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "../persistence/qihse_file.h"
#include "../persistence/qihse_container.h"
#include "../persistence/qihse_vector_store.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool fail_read, fail_create;
bool __real_qihse_file_pread_exact(qihse_file_t*, void*, size_t, uint64_t);
bool __wrap_qihse_file_pread_exact(qihse_file_t* f, void* p, size_t n, uint64_t o) {
    if (fail_read) { fail_read=false; errno=EIO; return false; }
    return __real_qihse_file_pread_exact(f,p,n,o);
}
bool __real_qihse_ctr_open_write(const char*, bool, qihse_container_t*);
bool __wrap_qihse_ctr_open_write(const char* path, bool create, qihse_container_t* c) {
    if (create && fail_create) { fail_create=false; errno=EIO; return false; }
    return __real_qihse_ctr_open_write(path,create,c);
}
static qihse_user_t* op;
static const float values[3][4]={{1,2,3,4},{5,6,7,8},{9,10,11,12}};
static const uint64_t ids[3]={1,2,3};
static void expect(qihse_vector_db_t db, unsigned i) {
    float got[4]; size_t dims=0;
    assert(qihse_vector_db_get_vector_by_id_user(db,op,ids[i],got,&dims));
    assert(dims==4 && !memcmp(got,values[i],sizeof(got)));
}
static size_t spilled(qihse_vector_db_t db) {
    size_t budget,ram,n;
    assert(qihse_vector_db_get_memory_usage(db,&budget,&ram,&n)); return n;
}
static qihse_vector_db_t create(const char* path) {
    qihse_vector_db_t db=qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,NULL,path); assert(db);
    assert(qihse_vector_db_add_vectors(db,&values[0][0],3,4,ids,NULL,NULL));
    assert(qihse_vector_db_flush(db)); return db;
}
static void make_cold(qihse_vector_db_t db) {
    assert(qihse_vector_db_set_memory_budget(db,1));
    /* Reads can heat rows; force the documented cold threshold for this fixture. */
    assert(qihse_vector_db_run_memory_maintenance(db));
    assert(spilled(db)>0);
}
static void test_flush(const char* path) {
    qihse_vector_db_t db=create(path); make_cold(db);
    float got[4]; size_t dims=0;
    fail_read=true; errno=0;
    assert(!qihse_vector_db_get_vector_by_id_user(db,op,ids[0],got,&dims) && !fail_read && errno==EIO);
    uint64_t fourth=4; assert(qihse_vector_db_add_vectors(db,values[0],1,4,&fourth,NULL,NULL));
    qihse_vector_db_persistence_stats_t before,after;
    assert(qihse_vector_db_get_persistence_stats(db,&before));
    fail_read=true; errno=0;
    assert(!qihse_vector_db_flush(db) && !fail_read && errno==EIO);
    assert(qihse_vector_db_get_persistence_stats(db,&after));
    assert(before.wal_bytes_pending==after.wal_bytes_pending && before.committed_generation==after.committed_generation);
    assert(spilled(db)>0);
    assert(qihse_vector_db_flush(db));
    qihse_vector_db_destroy(db);
    db=qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED); assert(db);
    assert(spilled(db)==0);
    for(unsigned i=0;i<3;i++) expect(db,i);
    qihse_vector_db_destroy(db);
}
static void test_disable_and_compact(const char* path) {
    qihse_vector_db_t db=create(path); make_cold(db);
    fail_read=true; errno=0;
    assert(!qihse_vector_db_set_memory_budget(db,0) && !fail_read && errno==EIO);
    size_t budget,ram,n; assert(qihse_vector_db_get_memory_usage(db,&budget,&ram,&n));
    assert(budget==1 && n>0);
    for(unsigned i=0;i<3;i++) expect(db,i);
    assert(qihse_vector_db_set_memory_budget(db,0)); assert(spilled(db)==0);
    /* A new batch has no recorded accesses; spill it and compact over holes. */
    uint64_t extra=4; assert(qihse_vector_db_add_vectors(db,values[0],1,4,&extra,NULL,NULL));
    make_cold(db);
    assert(qihse_vector_db_delete_by_id_user(db,op,ids[0]));
    assert(qihse_vector_db_compact(db));
    expect(db,1); expect(db,2);
    assert(qihse_vector_db_set_memory_budget(db,0));
    assert(qihse_vector_db_close(db));
    db=qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED); assert(db);
    expect(db,1); expect(db,2); assert(spilled(db)==0);
    qihse_vector_db_destroy(db);
}
static void test_scratch_ownership(const char* path) {
    qihse_vector_db_t a=create(path);
    char fixed[1024]; assert(snprintf(fixed,sizeof(fixed),"%s.spill",path)<(int)sizeof(fixed));
    int fd=open(fixed,O_WRONLY|O_CREAT|O_EXCL,0600); assert(fd>=0);
    assert(write(fd,"sentinel",8)==8 && close(fd)==0);
    make_cold(a);
    qihse_vector_db_t b=qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED); assert(b);
    make_cold(b);
    for(unsigned i=0;i<3;i++){expect(a,i);expect(b,i);}
    qihse_vector_db_destroy(b);
    for(unsigned i=0;i<3;i++)expect(a,i);
    fd=open(fixed,O_RDONLY); assert(fd>=0); char bytes[8];
    assert(read(fd,bytes,8)==8 && !memcmp(bytes,"sentinel",8) && close(fd)==0);
    qihse_vector_db_destroy(a); assert(unlink(fixed)==0);
    qihse_vector_db_t ro=qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED|QIHSE_VDB_OPEN_READ_ONLY|QIHSE_VDB_OPEN_MMAP); assert(ro);
    errno=0; assert(!qihse_vector_db_set_memory_budget(ro,1) && errno==EROFS);
    for(unsigned i=0;i<3;i++)expect(ro,i);
    assert(qihse_vector_db_build_fp16(ro));
    assert(qihse_vector_db_build_fp32(ro));
    qihse_vector_db_destroy(ro);
}
static void test_build(const char* path) {
    qihse_vector_db_t db=create(path); make_cold(db);
    assert(qihse_vector_db_build_fp16(db));
    for(unsigned i=0;i<3;i++)expect(db,i);
    qihse_vector_db_destroy(db);
}
static void test_without_tier_hint(const char* path) {
    qihse_index_row_t rows[3]={{0}};
    for(unsigned i=0;i<3;i++) {
        rows[i].vector_id=ids[i]; rows[i].vector_offset=i*sizeof(values[0]);
        rows[i].row_flags=QIHSE_ROW_F_LIVE; rows[i].commit_generation=1;
    }
    qihse_vector_store_flush_t image={0};
    image.vector_dims=4; image.commit_generation=1; image.rows=rows; image.row_count=3;
    image.vectors=values; image.vector_bytes=sizeof(values);
    assert(qihse_vector_store_flush(path,&image));
    qihse_vector_db_t db=qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,NULL,path,QIHSE_VDB_OPEN_FILE_BACKED);
    assert(db); make_cold(db);
    assert(qihse_vector_db_set_memory_budget(db,0));
    for(unsigned i=0;i<3;i++)expect(db,i);
    qihse_vector_db_destroy(db);
}
static int remove_entry(const char* p,const struct stat* s,int t,struct FTW* w) {
    (void)s;(void)t;(void)w; return remove(p);
}
int main(void) {
    char root[]="tests/vector-spill-recovery-XXXXXX"; assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR",root,1)==0);
    assert(setenv("QIHSE_FIPS_MODE","disabled",1)==0);
    assert(setenv("QIHSE_MEMORY_COLD_THRESHOLD","1e30",1)==0);
    qihse_test_container_keys(root);
    assert(qihse_auth_init()); assert(qihse_auth_bootstrap_operator("SpillRecoveryOperator123!"));
    op=qihse_auth_get_user(0); assert(op);
    char path[512]; snprintf(path,sizeof(path),"%s/flush.qdb",root); test_flush(path);
    snprintf(path,sizeof(path),"%s/compact.qdb",root); test_disable_and_compact(path);
    snprintf(path,sizeof(path),"%s/scratch.qdb",root); test_scratch_ownership(path);
    snprintf(path,sizeof(path),"%s/build.qdb",root); test_build(path);
    snprintf(path,sizeof(path),"%s/no-tier.qdb",root); test_without_tier_hint(path);
    snprintf(path,sizeof(path),"%s/create-fails.qdb",root);
    fail_create=true; errno=0;
    assert(!qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,NULL,path) && !fail_create && errno==EIO);
    qihse_auth_shutdown_rate_limiter(); qihse_auth_shutdown_volume_limiter(); qihse_audit_shutdown();
    assert(nftw(root,remove_entry,16,FTW_DEPTH|FTW_PHYS)==0);
    puts("PASS spill flush/compact/reopen, failed restore, scratch ownership and create errors");
    return 0;
}
