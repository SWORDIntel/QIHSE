/* Standalone W12.2 sidecar tests. The source fixture is caller-owned and
 * exact fallback receives the explicit principal, like an engine adapter. */
#define _POSIX_C_SOURCE 200809L
#include "quantization/include/qihse_turboquant_sidecar.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if(!(x)) { \
    fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); \
} } while(0)

typedef struct {
    qihse_tq_sidecar_row rows[3];
    size_t count;
    int exact_calls;
    int hidden_visible_calls;
    uint64_t tombstone;
    qihse_user_t *operator_user;
    bool revoke_in_exact;
} fixture;

static bool visible(const qihse_user_t *user,uint64_t id,void *opaque) {
    fixture *f=opaque;
    size_t i;
    CHECK(qihse_auth_user_is_active(user));
    if(id==2) ++f->hidden_visible_calls;
    if(id==f->tombstone) return false;
    for(i=0;i<f->count;i++) if(f->rows[i].id==id)
        return qihse_auth_can_access(user,f->rows[i].classification,f->rows[i].sci);
    return false;
}
static uint32_t row_crc(const uint8_t *data,size_t n) {
    uint32_t value=UINT32_MAX; size_t i; unsigned bit;
    for(i=0;i<n;i++) {
        value^=data[i];
        for(bit=0;bit<8;bit++)
            value=(value>>1)^((0u-(value&1u))&UINT32_C(0xedb88320));
    }
    return ~value;
}
static int exact(const qihse_user_t *user,const float *query,size_t dims,
                 qihse_tq_metric metric,qihse_tq_candidate *out,size_t capacity,
                 size_t *count,void *opaque) {
    fixture *f=opaque; size_t i,j,n=0;
    if(!qihse_auth_user_is_active(user)||dims!=2||!query||!out||!count)
        return EACCES;
    ++f->exact_calls;
    for(i=0;i<f->count;i++) {
        const qihse_tq_sidecar_row *r=&f->rows[i];
        double dot,score;
        if(!qihse_auth_can_access(user,r->classification,r->sci)||
           !visible(user,r->id,opaque)) continue;
        dot=(double)query[0]*r->vector[0]+(double)query[1]*r->vector[1];
        if(metric==QIHSE_TQ_L2_SQUARED) {
            double x=(double)query[0]-r->vector[0],y=(double)query[1]-r->vector[1];
            score=x*x+y*y;
        } else if(metric==QIHSE_TQ_COSINE) {
            double a=hypot(query[0],query[1]),b=hypot(r->vector[0],r->vector[1]);
            score=(a>0&&b>0)?dot/(a*b):0;
        } else score=dot;
        for(j=0;j<n;j++)
            if(metric==QIHSE_TQ_L2_SQUARED?
               score<out[j].estimate:(score>out[j].estimate)) break;
        if(j<capacity) {
            size_t end=n<capacity?n:capacity-1u;
            while(end>j) { out[end]=out[end-1u]; --end; }
            out[j]=(qihse_tq_candidate){r->id,score};
            if(n<capacity) ++n;
        }
    }
    *count=n;
    if(f->revoke_in_exact) {
        f->revoke_in_exact=false;
        CHECK(qihse_auth_destroy_user(f->operator_user,71));
    }
    return 0;
}

enum { BENCH_ROWS=64, BENCH_DIMS=16, BENCH_QUERIES=8, BENCH_REPEATS=3,
       BENCH_K=5, BENCH_POOL=8 };
typedef struct {
    float vectors[BENCH_ROWS][BENCH_DIMS];
    qihse_tq_sidecar_row side[BENCH_ROWS];
    uint32_t tenants[BENCH_ROWS];
    uint64_t projects[BENCH_ROWS];
    uint64_t generation;
    uint64_t hidden_id;
    uint64_t deny_during_score_id;
    bool stale_once;
    unsigned unexpected_fallback_calls;
    unsigned scored;
    unsigned hidden_scored;
} bench_fixture;
static uint32_t bench_rng(uint32_t *state) {
    uint32_t x=*state;
    x^=x<<13; x^=x>>17; x^=x<<5; *state=x; return x;
}
static int bench_visible(const qihse_user_t *user,uint64_t id,
                         qihse_tq_scope scope,uint64_t generation,void *opaque) {
    bench_fixture *f=opaque; size_t i;
    if(f->stale_once) { f->stale_once=false; return ESTALE; }
    if(generation!=f->generation) return ESTALE;
    if(id<1000||id>=1000+BENCH_ROWS) return EACCES;
    i=(size_t)(id-1000);
    if(id==f->hidden_id||f->tenants[i]!=scope.tenant_id||
       f->projects[i]!=scope.project_id||
       !qihse_auth_can_access(user,f->side[i].classification,f->side[i].sci))
        return EACCES;
    return 0;
}
static int bench_score(const qihse_user_t *user,uint64_t id,
                       qihse_tq_scope scope,uint64_t generation,
                       const float *query,size_t dims,qihse_tq_metric metric,
                       double *out,void *opaque) {
    bench_fixture *f=opaque; size_t j,i; double dot=0,qn=0,vn=0,l2=0;
    int rc=bench_visible(user,id,scope,generation,opaque);
    if(rc) { ++f->hidden_scored; return rc; }
    if(dims!=BENCH_DIMS||!out) return EINVAL;
    if(id==f->deny_during_score_id) {
        f->deny_during_score_id=0;
        f->hidden_id=id;
        return EACCES;
    }
    i=(size_t)(id-1000); ++f->scored;
    for(j=0;j<dims;j++) {
        double a=query[j],b=f->vectors[i][j],difference=a-b;
        dot+=a*b; qn+=a*a; vn+=b*b; l2+=difference*difference;
    }
    *out=metric==QIHSE_TQ_DOT?dot:
         metric==QIHSE_TQ_COSINE?(qn&&vn?dot/sqrt(qn*vn):0):l2;
    return 0;
}
static int bench_exact(const qihse_user_t *user,qihse_tq_scope scope,
                       uint64_t generation,const float *query,size_t dims,
                       qihse_tq_metric metric,qihse_tq_candidate *out,
                       size_t capacity,size_t *out_count,void *opaque) {
    size_t i,j,n=0; double score; int rc;
    if(!out||!out_count) return EINVAL;
    for(i=0;i<BENCH_ROWS;i++) {
        rc=bench_visible(user,1000+i,scope,generation,opaque);
        if(rc==EACCES) continue;
        if(rc) return rc;
        rc=bench_score(user,1000+i,scope,generation,query,dims,metric,&score,opaque);
        if(rc) return rc;
        for(j=0;j<n;j++)
            if(metric==QIHSE_TQ_L2_SQUARED?
               (score<out[j].estimate||(score==out[j].estimate&&1000+i<out[j].id)):
               (score>out[j].estimate||(score==out[j].estimate&&1000+i<out[j].id)))
                break;
        if(j<capacity) {
            size_t end=n<capacity?n:capacity-1;
            while(end>j) { out[end]=out[end-1]; --end; }
            out[j]=(qihse_tq_candidate){1000+i,score};
            if(n<capacity) ++n;
        }
    }
    *out_count=n; return 0;
}
static int unexpected_success_fallback(
    const qihse_user_t *user,qihse_tq_scope scope,uint64_t generation,
    const float *query,size_t dims,qihse_tq_metric metric,
    qihse_tq_candidate *out,size_t capacity,size_t *count,void *opaque) {
    bench_fixture *f=opaque;
    (void)user; (void)scope; (void)generation; (void)query;
    (void)dims; (void)metric;
    ++f->unexpected_fallback_calls;
    if(!capacity) return EINVAL;
    out[0]=(qihse_tq_candidate){999,999};
    *count=1;
    return 0;
}
static uint64_t bench_ns(void) {
    struct timespec t; CHECK(clock_gettime(CLOCK_MONOTONIC,&t)==0);
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static int compare_u64(const void *a,const void *b) {
    uint64_t x=*(const uint64_t *)a,y=*(const uint64_t *)b;
    return (x>y)-(x<y);
}
static void test_scoped_differential(qihse_user_t *operator_user,
                                     qihse_user_t *low) {
    bench_fixture *f=calloc(1,sizeof *f);
    qihse_tq_profile *profile=NULL;
    qihse_tq_config config={BENCH_DIMS,3,QIHSE_TQ_MSE,UINT64_C(0x12345678),0};
    qihse_tq_scope scope={42,7};
    char file[]="build/w12/scoped_file_XXXXXX";
    char absent[]="build/w12/scoped_missing_XXXXXX";
    uint32_t state=UINT32_C(0x91234567);
    uint64_t samples[BENCH_QUERIES*BENCH_REPEATS];
    uint64_t exact_samples[BENCH_QUERIES*BENCH_REPEATS];
    size_t i,j,q,repeat,found,truth_count,pool_count,total_hits=0,total_truth=0;
    qihse_tq_candidate truth[BENCH_K],actual[BENCH_K];
    float query[BENCH_DIMS]; bool used; int fd;
    struct stat st;
    CHECK(f!=NULL);
    f->generation=7;
    for(i=0;i<BENCH_ROWS;i++) {
        for(j=0;j<BENCH_DIMS;j++)
            f->vectors[i][j]=(float)((int32_t)(bench_rng(&state)>>8)-(1<<23))/
                              (float)(1<<23);
        f->tenants[i]=i%4==0?43:42;
        f->projects[i]=i%5==0?8:7;
        f->side[i]=(qihse_tq_sidecar_row){
            1000+i,(uint16_t)(i%7==0?2:0),(uint16_t)(i%7==0?1:0),f->vectors[i]};
    }
    CHECK(qihse_tq_profile_create(&config,&profile)==0);
    fd=mkstemp(file); CHECK(fd>=0); close(fd); CHECK(unlink(file)==0);
    fd=mkstemp(absent); CHECK(fd>=0); close(fd); CHECK(unlink(absent)==0);
    CHECK(qihse_tq_sidecar_publish(file,operator_user,profile,7,
                                    f->side,BENCH_ROWS)==0);
    CHECK(stat(file,&st)==0);
    for(q=0;q<BENCH_QUERIES;q++) {
        for(j=0;j<BENCH_DIMS;j++)
            query[j]=(float)((int32_t)(bench_rng(&state)>>8)-(1<<23))/
                     (float)(1<<23);
        CHECK(bench_exact(low,scope,7,query,BENCH_DIMS,QIHSE_TQ_DOT,
                          truth,BENCH_K,&truth_count,f)==0);
        CHECK(truth_count==BENCH_K);
        for(repeat=0;repeat<BENCH_REPEATS;repeat++) {
            uint64_t start=bench_ns();
            CHECK(qihse_tq_sidecar_search_scoped(
                file,low,scope,7,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
                BENCH_POOL,bench_visible,bench_score,bench_exact,f,
                actual,BENCH_K,&found,&used)==0);
            samples[q*BENCH_REPEATS+repeat]=bench_ns()-start;
            CHECK(used&&found==BENCH_K);
            if(repeat==0) {
                for(i=0;i<found;i++) {
                    CHECK(actual[i].id!=0);
                    CHECK(bench_visible(low,actual[i].id,scope,7,f)==0);
                    for(j=0;j<truth_count;j++) if(actual[i].id==truth[j].id) ++total_hits;
                }
                total_truth+=truth_count;
            }
            start=bench_ns();
            CHECK(qihse_tq_sidecar_search_scoped(
                absent,low,scope,7,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
                BENCH_POOL,bench_visible,bench_score,bench_exact,f,
                actual,BENCH_K,&found,&used)==0);
            exact_samples[q*BENCH_REPEATS+repeat]=bench_ns()-start;
            CHECK(!used&&found==truth_count);
            for(i=0;i<found;i++) CHECK(actual[i].id==truth[i].id);
        }
        CHECK(qihse_tq_sidecar_search_scoped(
            file,low,scope,7,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
            BENCH_ROWS,bench_visible,bench_score,bench_exact,f,
            actual,BENCH_K,&pool_count,&used)==0);
        CHECK(used&&pool_count==truth_count);
        for(i=0;i<pool_count;i++) {
            CHECK(actual[i].id==truth[i].id);
            CHECK(fabs(actual[i].estimate-truth[i].estimate)<1e-9);
        }
    }
    CHECK(f->hidden_scored==0);
    for(i=QIHSE_TQ_COSINE;i<=QIHSE_TQ_L2_SQUARED;i++) {
        qihse_tq_metric metric=(qihse_tq_metric)i;
        CHECK(bench_exact(low,scope,7,query,BENCH_DIMS,metric,
                          truth,BENCH_K,&truth_count,f)==0);
        CHECK(qihse_tq_sidecar_search_scoped(
            file,low,scope,7,profile,query,BENCH_DIMS,metric,
            BENCH_ROWS,bench_visible,bench_score,bench_exact,f,
            actual,BENCH_K,&found,&used)==0);
        CHECK(used&&found==truth_count);
        for(j=0;j<found;j++) {
            CHECK(actual[j].id==truth[j].id);
            CHECK(fabs(actual[j].estimate-truth[j].estimate)<1e-9);
        }
    }
    qsort(samples,BENCH_QUERIES*BENCH_REPEATS,sizeof samples[0],compare_u64);
    qsort(exact_samples,BENCH_QUERIES*BENCH_REPEATS,
          sizeof exact_samples[0],compare_u64);
    printf("W12 scoped synthetic: recall@5 pool8=%zu/%zu (%.3f), "
           "pool64=%d/%d, sidecar p50=%" PRIu64 " ns, p95=%" PRIu64
           " ns, exact fallback p50=%" PRIu64 " ns, p95=%" PRIu64
           " ns, sidecar=%jd bytes, FP32 payload=%zu bytes\n",
           total_hits,total_truth,(double)total_hits/total_truth,
           BENCH_QUERIES*BENCH_K,BENCH_QUERIES*BENCH_K,
           samples[11],samples[22],exact_samples[11],exact_samples[22],
           (intmax_t)st.st_size,
           sizeof f->vectors);
    memcpy(query,f->vectors[7],sizeof query);
    CHECK(f->side[7].classification==2&&f->side[7].sci==1);
    CHECK(qihse_tq_sidecar_search_scoped(
        file,low,scope,7,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
        BENCH_ROWS,bench_visible,bench_score,bench_exact,f,
        actual,BENCH_K,&found,&used)==0);
    CHECK(used&&found==BENCH_K);
    for(i=0;i<found;i++) CHECK(actual[i].id!=1007);
    { qihse_tq_scope foreign={99,99};
      CHECK(qihse_tq_sidecar_search_scoped(
          file,low,foreign,7,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
          BENCH_ROWS,bench_visible,bench_score,bench_exact,f,
          actual,BENCH_K,&found,&used)==0);
      CHECK(used&&found==0);
    }
    CHECK(f->hidden_scored==0);
    f->deny_during_score_id=1001;
    memcpy(query,f->vectors[1],sizeof query);
    CHECK(qihse_tq_sidecar_search_scoped(
        file,low,scope,7,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
        BENCH_ROWS,bench_visible,bench_score,bench_exact,f,
        actual,BENCH_K,&found,&used)==0);
    CHECK(!used&&f->hidden_id==1001);
    for(i=0;i<found;i++) CHECK(actual[i].id!=1001);
    CHECK(bench_exact(low,scope,7,query,BENCH_DIMS,QIHSE_TQ_DOT,
                      truth,BENCH_K,&truth_count,f)==0);
    CHECK(found==truth_count);
    for(i=0;i<found;i++) CHECK(actual[i].id==truth[i].id);
    f->hidden_id=0;
    CHECK(bench_exact(low,scope,7,query,BENCH_DIMS,QIHSE_TQ_DOT,
                      truth,BENCH_K,&truth_count,f)==0);
    f->stale_once=true; found=999; used=true;
    actual[0]=(qihse_tq_candidate){999,999};
    CHECK(qihse_tq_sidecar_search_scoped(
        file,low,scope,7,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
        BENCH_POOL,bench_visible,bench_score,unexpected_success_fallback,f,
        actual,BENCH_K,&found,&used)==ESTALE);
    CHECK(!f->stale_once&&f->unexpected_fallback_calls==0);
    CHECK(found==999&&used&&actual[0].id==999);
    f->generation=8;
    CHECK(qihse_tq_sidecar_search_scoped(
        file,low,scope,8,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
        BENCH_POOL,bench_visible,bench_score,bench_exact,f,
        actual,BENCH_K,&found,&used)==0);
    CHECK(!used&&found==truth_count);
    for(i=0;i<found;i++) CHECK(actual[i].id==truth[i].id);
    found=999; used=true; actual[0]=(qihse_tq_candidate){999,999};
    CHECK(qihse_tq_sidecar_search_scoped(
        file,low,scope,7,profile,query,BENCH_DIMS,QIHSE_TQ_DOT,
        BENCH_POOL,bench_visible,bench_score,bench_exact,f,
        actual,BENCH_K,&found,&used)==ESTALE);
    CHECK(found==999&&used&&actual[0].id==999);
    CHECK(unlink(file)==0);
    qihse_tq_profile_destroy(profile); free(f);
}

int main(void) {
    char auth_dir[]="build/w12/sidecar_auth_XXXXXX";
    char file[]="build/w12/sidecar_file_XXXXXX";
    float a[2]={0.5f,0.5f}, secret[2]={1.0f,0.0f},b[2]={0.0f,1.0f};
    float query[2]={1.0f,0.0f};
    qihse_tq_config config={2,3,QIHSE_TQ_MSE,UINT64_C(12345),0};
    qihse_tq_profile *profile=NULL,*opened=NULL;
    qihse_user_t *op,*low;
    qihse_tq_candidate result[3],before[3],only_low[3];
    size_t count=999,before_n=0,only_low_n=0,profile_bytes=0;
    bool used=false; fixture f={0}; int fd;
    CHECK(mkdtemp(auth_dir)!=NULL);
    CHECK(chmod(auth_dir,0700)==0);
    CHECK(setenv("QIHSE_DATA_DIR",auth_dir,1)==0);
    CHECK(setenv("QIHSE_ALLOW_INSECURE_CONTAINER","1",0)==0);
    CHECK(setenv("QIHSE_ENFORCE_INTEGRITY","1",1)==0);
    CHECK(qihse_auth_init());
    CHECK(qihse_auth_bootstrap_operator("W12SidecarTestPass123!"));
    op=qihse_auth_get_user(0);
    CHECK(op!=NULL);
    f.operator_user=op;
    low=qihse_auth_create_user(op,71,QIHSE_ROLE_ANALYST,0,0,
                               "W12LowUserPass123!",false);
    CHECK(low!=NULL);
    CHECK(qihse_tq_profile_create(&config,&profile)==0);
    f.rows[0]=(qihse_tq_sidecar_row){1,0,0,a};
    f.rows[1]=(qihse_tq_sidecar_row){2,2,1,secret};
    f.rows[2]=(qihse_tq_sidecar_row){3,0,0,b};
    f.count=3;
    fd=mkstemp(file); CHECK(fd>=0); close(fd); CHECK(unlink(file)==0);
    CHECK(qihse_tq_sidecar_publish(file,low,profile,1,f.rows,f.count)==EACCES);
    CHECK(qihse_tq_sidecar_publish(file,op,profile,1,f.rows,f.count)==0);
    CHECK(qihse_tq_sidecar_open_profile(file,low,1,&opened)==0);
    qihse_tq_profile_destroy(opened); opened=NULL;
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,1,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==0);
    CHECK(used&&count==2&&f.exact_calls==0&&f.hidden_visible_calls==0);
    CHECK(result[0].id!=2&&result[1].id!=2);
    memcpy(before,result,count*sizeof *result); before_n=count;

    /* A forged low label with a recomputed CRC cannot bypass live source
     * clearance checked by the mandatory scope callback. */
    { size_t code_bytes=0,row_bytes; uint8_t *row; off_t offset; uint32_t sum;
      CHECK(qihse_tq_profile_serialized_size(profile,&profile_bytes)==0);
      CHECK(qihse_tq_code_size(&config,&code_bytes)==0);
      row_bytes=16+code_bytes+4;
      row=malloc(row_bytes); CHECK(row!=NULL);
      offset=(off_t)(64+profile_bytes+row_bytes);
      fd=open(file,O_RDWR); CHECK(fd>=0);
      CHECK(pread(fd,row,row_bytes,offset)==(ssize_t)row_bytes);
      row[8]=row[9]=row[10]=row[11]=0;
      sum=row_crc(row,row_bytes-4);
      row[row_bytes-4]=(uint8_t)sum;
      row[row_bytes-3]=(uint8_t)(sum>>8);
      row[row_bytes-2]=(uint8_t)(sum>>16);
      row[row_bytes-1]=(uint8_t)(sum>>24);
      CHECK(pwrite(fd,row,row_bytes,offset)==(ssize_t)row_bytes);
      close(fd); free(row);
      CHECK(qihse_tq_sidecar_candidates_or_exact(
          file,low,1,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
          result,3,&count,&used)==0);
      CHECK(used&&count==before_n&&memcmp(result,before,count*sizeof *result)==0);
      CHECK(f.hidden_visible_calls==1);
      CHECK(qihse_tq_sidecar_publish(file,op,profile,1,f.rows,f.count)==0);
    }

    /* High record present versus absent must not alter low result/order. */
    f.rows[1]=f.rows[2]; f.count=2;
    CHECK(qihse_tq_sidecar_publish(file,op,profile,2,f.rows,f.count)==0);
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,2,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        only_low,3,&only_low_n,&used)==0);
    CHECK(used&&only_low_n==before_n);
    CHECK(memcmp(before,only_low,before_n*sizeof *before)==0);
    f.tombstone=3;
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,2,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==0);
    CHECK(used&&count==1&&result[0].id==1);
    f.tombstone=0;

    /* Stale generation never mixes codes and falls back to authoritative FP32. */
    f.rows[1]=(qihse_tq_sidecar_row){2,2,1,secret};
    f.rows[2]=(qihse_tq_sidecar_row){3,0,0,b}; f.count=3;
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,1,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==0);
    CHECK(!used&&f.exact_calls==1&&count==2);
    CHECK(qihse_tq_sidecar_open_profile(file,low,1,&opened)==ESTALE);
    CHECK(opened==NULL);

    /* Corrupt an authorized row's code, then the header: both use exact. */
    f.rows[1]=f.rows[2]; f.count=2;
    CHECK(qihse_tq_sidecar_publish(file,op,profile,2,f.rows,f.count)==0);
    CHECK(qihse_tq_profile_serialized_size(profile,&profile_bytes)==0);
    fd=open(file,O_RDWR); CHECK(fd>=0);
    { uint8_t byte;
      off_t offset=(off_t)(64+profile_bytes+16);
      CHECK(pread(fd,&byte,1,offset)==1);
      byte^=0x80u;
      CHECK(pwrite(fd,&byte,1,offset)==1);
    }
    close(fd);
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,2,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==0);
    CHECK(!used&&f.exact_calls==2);

    /* Corrupt header and absent sidecar use the same exact callback. */
    fd=open(file,O_WRONLY); CHECK(fd>=0);
    CHECK(pwrite(fd,"!",1,0)==1); close(fd);
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,2,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==0);
    CHECK(!used&&f.exact_calls==3);
    CHECK(unlink(file)==0);
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,2,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==0);
    CHECK(!used&&f.exact_calls==4);

    test_scoped_differential(op,low);

    /* NULL principal cannot trigger candidate scan or exact callback. */
    count=987; used=true;
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,NULL,2,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==EACCES);
    CHECK(count==987&&used&&f.exact_calls==4);

    /* Revocation during fallback is caught by the final generation check;
     * no partial caller output or stale principal survives it. */
    result[0]=(qihse_tq_candidate){999,999.0};
    count=987; used=true; f.revoke_in_exact=true;
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,2,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==EACCES);
    CHECK(count==987&&used&&result[0].id==999&&result[0].estimate==999.0);
    CHECK(f.exact_calls==5);
    CHECK(qihse_tq_sidecar_candidates_or_exact(
        file,low,2,profile,query,2,QIHSE_TQ_DOT,visible,exact,&f,
        result,3,&count,&used)==EACCES);
    CHECK(count==987&&used&&f.exact_calls==5);
    CHECK(qihse_tq_sidecar_open_profile(file,low,2,&opened)==EACCES);
    CHECK(opened==NULL);
    CHECK(qihse_tq_sidecar_open_profile(file,NULL,2,&opened)==EACCES);
    CHECK(qihse_tq_sidecar_publish(file,low,profile,3,f.rows,f.count)==EACCES);
    CHECK(qihse_tq_sidecar_publish(file,NULL,profile,3,f.rows,f.count)==EACCES);
    qihse_tq_profile_destroy(profile);
    puts("W12.2 sidecar generation, corruption, fallback and auth negatives: passed");
    return 0;
}
