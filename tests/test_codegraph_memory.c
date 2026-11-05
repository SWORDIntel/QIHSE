#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include "qihse_codegraph_storage.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#define PASSWORD "MemorySnapshotOperator1!"
static char runtime[PATH_MAX];
static int cleanup(const char *path, const struct stat *st, int flags, struct FTW *walk) {
    (void)st; (void)flags; (void)walk; return remove(path);
}
static qihse_user_t *bootstrap(void) {
    const char *tmp = getenv("TMPDIR"); if (!tmp || !*tmp) tmp = ".";
    assert(snprintf(runtime, sizeof(runtime), "%s/qihse-memory-test-XXXXXX", tmp) < (int)sizeof(runtime));
    assert(mkdtemp(runtime));
    char full[PATH_MAX]; assert(realpath(runtime, full)); strcpy(runtime, full);
    assert(setenv("QIHSE_DATA_DIR", runtime, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD); assert(op); return op;
}
static void finish(void) { qihse_audit_shutdown(); assert(nftw(runtime, cleanup, 16, FTW_DEPTH | FTW_PHYS) == 0); }
static void value_is(qihse_kv_store_t *store, qihse_user_t *user, const char *key, const char *want) {
    char *v = qihse_kv_get_user(store, key, user); assert(want ? v && !strcmp(v, want) : !v); free(v);
}
static FILE *fixture(void) {
    FILE *f = tmpfile(); assert(f);
    /* All versions of metadata: public, protected SCI, expiry, tombstone. */
    assert(fputs("6 8 0 0 0 0 11\npublicretained\n"
                 "9 6 4000000000000 4 2 0 22\nprotectedsecret\n"
                 "7 3 1 4 2 0 33\nexpiredold\n"
                 "7 0 0 4 2 1 44\ndeleted\n", f) >= 0);
    rewind(f); return f;
}
static void reject(FILE *f, qihse_user_t *u, size_t bytes, size_t records, int error) {
    rewind(f); errno = 0; assert(!qihse_kv_open_snapshot_user(f,u,bytes,records)); assert(errno == error);
}
static unsigned long long write_count(void) {
    FILE *f = fopen("/proc/self/io", "r"); assert(f);
    char line[128]; unsigned long long value = 0;
    while (fgets(line, sizeof(line), f)) if (sscanf(line,"wchar: %llu",&value)==1) break;
    fclose(f); return value;
}
static long resident_kib(void) {
    FILE *f = fopen("/proc/self/status", "r"); assert(f);
    char line[128]; long rss = 0;
    while (fgets(line, sizeof(line), f)) if (sscanf(line,"VmRSS: %ld",&rss)==1) break;
    fclose(f); return rss;
}
static double seconds(struct timeval v) { return v.tv_sec + v.tv_usec / 1000000.0; }
static double monotonic(void) { struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC,&t)); return t.tv_sec+t.tv_nsec/1e9; }
static int bench(const char *path, const char *mode) {
    qihse_user_t *op = bootstrap();
    qihse_kv_store_t *s = NULL;
    if (!strcmp(mode,"disk")) { s = qihse_kv_store_create_user(op); assert(s); }
    struct rusage before, after; assert(!getrusage(RUSAGE_SELF,&before));
    unsigned long long writes = write_count(); double start = monotonic();
    if (s) assert(cg_storage_load(s,path,op));
    else s = cg_storage_open(path,op,256u*1024u*1024u,1000000u);
    assert(s);
    double wall = monotonic()-start; writes = write_count()-writes;
    assert(!getrusage(RUSAGE_SELF,&after));
    printf("%s records=%zu wall_ms=%.3f cpu_ms=%.3f peak_rss_kib=%ld resident_rss_kib=%ld write_bytes=%llu\n",mode,
        qihse_kv_count_user(s,op), wall*1000,
        (seconds(after.ru_utime)+seconds(after.ru_stime)-seconds(before.ru_utime)-seconds(before.ru_stime))*1000,
        after.ru_maxrss,resident_kib(),writes);
    qihse_kv_store_destroy(s); finish(); return 0;
}
int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1],"--bench")) return bench(argv[2],argv[3]);
    qihse_user_t *op = bootstrap();
    assert(qihse_auth_create_user(op, 73, QIHSE_ROLE_ANALYST,0,0,PASSWORD,false));
    assert(qihse_auth_create_user(op, 74, QIHSE_ROLE_ANALYST,4,0,PASSWORD,false));
    qihse_user_t *low=qihse_auth_authenticate_id(73,PASSWORD), *no_sci=qihse_auth_authenticate_id(74,PASSWORD);
    assert(low && no_sci);
    FILE *f=fixture();
    reject(f,NULL,4096,10,EACCES); reject(f,low,4096,10,EACCES); reject(f,no_sci,4096,10,EACCES);
    reject(f,op,32,10,EFBIG); reject(f,op,4096,1,E2BIG);
    rewind(f); qihse_kv_store_t *s=qihse_kv_open_snapshot_user(f,op,4096,10); assert(s);
    value_is(s,op,"public","retained"); value_is(s,op,"protected","secret"); value_is(s,low,"protected",NULL);
    value_is(s,op,"expired",NULL); value_is(s,op,"deleted",NULL);
    qihse_kv_record_meta_t m; assert(qihse_kv_meta_user(s,"protected",op,&m));
    assert(m.classification==4 && m.sci_compartment==2 && m.change_seq==22 && m.expire_time_ms==4000000000000ULL && m.flags==0);
    uint64_t seq; bool tomb;
    assert(qihse_kv_change_seq_user(s,"deleted",op,&seq,&tomb) && seq==44 && tomb);
    assert(qihse_kv_change_seq(s)==44);
    assert(!qihse_kv_store_data_directory(s));
    assert(!qihse_kv_set_user(s,"public","change",0,0,op));
    assert(qihse_kv_compare_set_user(s,"public","retained","change",0,0,op) == QIHSE_KV_CAS_FAILED);
    assert(!qihse_kv_del_user(s,"public",op));
    assert(!qihse_kv_expire(s,"public",100,op)); assert(!qihse_kv_clear_user(s,op)); assert(!qihse_kv_sync_store(s));
    qihse_kv_bulk_load_begin(s); assert(!qihse_kv_set_user(s,"public","change",0,0,op)); qihse_kv_bulk_load_end(s);
    qihse_kv_replica_record_t row={.key="replica",.value="value",.change_seq=99};
    assert(!qihse_kv_apply_replica_record(s,&row,op)); qihse_kv_sweep_expired(s);
    value_is(s,op,"public","retained");
    char compact[PATH_MAX], legacy[PATH_MAX];
    assert(snprintf(compact,sizeof(compact),"%s/compact.kv",runtime)<(int)sizeof(compact));
    assert(snprintf(legacy,sizeof(legacy),"%s/legacy.kv",runtime)<(int)sizeof(legacy));
    assert(cg_storage_save(s,compact,op)); assert(qihse_kv_save_user(s,legacy,op)==0);
    assert(qihse_kv_load_user(s,legacy,op) != 0); /* immutable even for Operator */
    qihse_kv_store_t *copy=cg_storage_open(compact,op,4096,10); assert(copy); value_is(copy,op,"protected","secret");
    assert(qihse_kv_meta_user(copy,"protected",op,&m) && m.change_seq==22 && m.classification==4 && m.sci_compartment==2);
    qihse_kv_store_destroy(copy);
    assert(!cg_storage_open(compact,low,4096,10) && errno==EACCES);
    assert(!cg_storage_open(compact,op,32,10) && errno==EFBIG);
    assert(!cg_storage_open(compact,op,4096,1) && errno==E2BIG);
    assert(!cg_storage_open(legacy,low,4096,10) && errno==EACCES);
    copy=cg_storage_open(legacy,op,4096,10); assert(copy); qihse_kv_store_destroy(copy);
    int fd=open(compact,O_RDWR); assert(fd>=0); off_t length=lseek(fd,0,SEEK_END); assert(length>0);
    assert(ftruncate(fd,length-1)==0); close(fd);
    assert(!cg_storage_open(compact,op,4096,10)); value_is(s,op,"protected","secret");
    FILE *bad=tmpfile(); assert(bad); fputs("1 1 0 0 0 0 1\nkv\n1 1 0 0 0 0 2\nkv\n",bad);
    reject(bad,op,4096,10,EINVAL); fclose(bad);
    bad=tmpfile(); assert(bad); fputs("1 100000 0 0 0 0 1\nx",bad); reject(bad,op,4096,10,EFBIG); fclose(bad);
    assert(qihse_auth_destroy_user(op,73)); reject(f,low,4096,10,EACCES);
    char wal[PATH_MAX]; assert(snprintf(wal,sizeof(wal),"%s/wal.log",runtime)<(int)sizeof(wal));
    assert(access(wal,F_OK)!=0); /* no constructor/reader/sync created disk state */
    fclose(f); qihse_kv_store_destroy(s); finish();
    puts("CodeGraph memory snapshot: metadata, immutable, bounded, legacy, corrupt and auth tests passed"); return 0;
}
