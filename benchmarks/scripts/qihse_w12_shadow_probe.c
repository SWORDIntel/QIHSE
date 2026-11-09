/* W12.6 offline shadow fixture. No production route or QIHSE store access. */
#define _POSIX_C_SOURCE 200809L
#include "qihse_turboquant_sidecar.h"
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { ROWS=3, DIMS=2, QUERIES=3, REPEATS=5, SAMPLES=QUERIES*REPEATS };
typedef struct {
    float vectors[ROWS][DIMS];
    qihse_tq_sidecar_row rows[ROWS];
    uint64_t generation;
} source;
static uint64_t ns(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static int visible(const qihse_user_t *user,uint64_t id,qihse_tq_scope scope,
                   uint64_t generation,void *opaque) {
    source *s=opaque; size_t i;
    if(generation!=s->generation) return ESTALE;
    if(!qihse_auth_user_is_active(user)||scope.tenant_id!=42||scope.project_id!=7)
        return EACCES;
    if(id<1||id>ROWS) return EACCES;
    i=(size_t)(id-1);
    return qihse_auth_can_access(user,s->rows[i].classification,s->rows[i].sci)?
        0:EACCES;
}
static int exact_score(const qihse_user_t *user,uint64_t id,qihse_tq_scope scope,
                       uint64_t generation,const float *query,size_t dimensions,
                       qihse_tq_metric metric,double *out,void *opaque) {
    source *s=opaque; size_t i;
    int rc=visible(user,id,scope,generation,opaque);
    if(rc) return rc;
    if(!out||!query||dimensions!=DIMS||metric!=QIHSE_TQ_DOT) return EINVAL;
    i=(size_t)(id-1);
    *out=(double)query[0]*s->vectors[i][0]+
         (double)query[1]*s->vectors[i][1];
    return 0;
}
static int exact_all(const qihse_user_t *user,qihse_tq_scope scope,
                     uint64_t generation,const float *query,size_t dimensions,
                     qihse_tq_metric metric,qihse_tq_candidate *out,
                     size_t capacity,size_t *count,void *opaque) {
    size_t i,n=0; double score; int rc;
    if(!out||!count||!capacity) return EINVAL;
    for(i=1;i<=ROWS;i++) {
        rc=exact_score(user,i,scope,generation,query,dimensions,metric,&score,opaque);
        if(rc==EACCES) continue;
        if(rc) return rc;
        if(!n||score>out[0].estimate||
           (score==out[0].estimate&&i<out[0].id))
            out[0]=(qihse_tq_candidate){i,score};
        n=1;
    }
    *count=n; return 0;
}
static void samples(const char *label,const uint64_t *values) {
    size_t i;
    printf("%s",label);
    for(i=0;i<SAMPLES;i++) printf(",%" PRIu64,values[i]);
    putchar('\n');
}
int main(int argc,char **argv) {
    char auth_reason[128];
    qihse_user_t *operator_user,*low;
    qihse_tq_profile *profile=NULL;
    qihse_tq_config config={DIMS,3,QIHSE_TQ_MSE,UINT64_C(0x1206),0};
    qihse_tq_scope scope={42,7};
    float queries[QUERIES][DIMS]={{1,0},{0,1},{0.7f,0.3f}};
    source s={0},original={0};
    qihse_tq_candidate result[1],truth[1];
    uint64_t side_ns[SAMPLES],exact_ns[SAMPLES],start;
    struct stat st; size_t qi,rep,count,truth_count,hits=0,rollback=0;
    bool used; int rc=2;
    if(argc!=3||!argv[1]||!*argv[1]||!argv[2]||!*argv[2]||
       !getenv("QIHSE_DATA_DIR")) return 2;
    if(!qihse_audit_context_usable(auth_reason,sizeof auth_reason)) {
        fprintf(stderr,"audit directory: %s\n",auth_reason); return 2;
    }
    setenv("QIHSE_ALLOW_INSECURE_CONTAINER","1",0);
    setenv("QIHSE_ENFORCE_INTEGRITY","1",1);
    if(!qihse_auth_init()||
       !qihse_auth_bootstrap_operator("W12ShadowOfflinePass123!")) return 3;
    operator_user=qihse_auth_get_user(0);
    if(!operator_user) return 3;
    low=qihse_auth_create_user(operator_user,72,QIHSE_ROLE_ANALYST,0,0,
                               "W12ShadowLowPass123!",false);
    if(!low) return 3;
    s.vectors[0][0]=0.6f; s.vectors[0][1]=0.4f;
    s.vectors[1][0]=0.2f; s.vectors[1][1]=0.8f;
    s.vectors[2][0]=1.0f; s.vectors[2][1]=0.0f;
    s.generation=7;
    s.rows[0]=(qihse_tq_sidecar_row){1,0,0,s.vectors[0]};
    s.rows[1]=(qihse_tq_sidecar_row){2,0,0,s.vectors[1]};
    s.rows[2]=(qihse_tq_sidecar_row){3,2,1,s.vectors[2]};
    memcpy(&original.vectors,&s.vectors,sizeof s.vectors);
    if(qihse_tq_profile_create(&config,&profile)) return 3;
    if(qihse_tq_sidecar_publish(argv[1],operator_user,profile,7,s.rows,ROWS)||
       stat(argv[1],&st)) goto done;
    for(qi=0;qi<QUERIES;qi++) {
        if(exact_all(low,scope,7,queries[qi],DIMS,QIHSE_TQ_DOT,
                     truth,1,&truth_count,&s)||truth_count!=1) goto done;
        for(rep=0;rep<REPEATS;rep++) {
            size_t index=qi*REPEATS+rep;
            start=ns();
            if(qihse_tq_sidecar_search_scoped(
                argv[1],low,scope,7,profile,queries[qi],DIMS,QIHSE_TQ_DOT,
                2,visible,exact_score,exact_all,&s,
                result,1,&count,&used)) goto done;
            side_ns[index]=ns()-start;
            if(!used||count!=1||result[0].id==3) goto done;
            if(rep==0&&result[0].id==truth[0].id) ++hits;
            start=ns();
            if(qihse_tq_sidecar_search_scoped(
                argv[2],low,scope,7,profile,
                queries[qi],DIMS,QIHSE_TQ_DOT,2,visible,exact_score,exact_all,
                &s,result,1,&count,&used)) goto done;
            exact_ns[index]=ns()-start;
            if(used||count!=1||result[0].id!=truth[0].id) goto done;
        }
    }
    /* Rollback changes only the derived sidecar. The canonical caller-owned
     * FP32 array remains byte-identical and all queries use exact fallback. */
    if(unlink(argv[1])) goto done;
    if(memcmp(&original.vectors,&s.vectors,sizeof s.vectors)) goto done;
    for(qi=0;qi<QUERIES;qi++) {
        if(exact_all(low,scope,7,queries[qi],DIMS,QIHSE_TQ_DOT,
                     truth,1,&truth_count,&s)) goto done;
        if(qihse_tq_sidecar_search_scoped(
            argv[1],low,scope,7,profile,queries[qi],DIMS,QIHSE_TQ_DOT,
            2,visible,exact_score,exact_all,&s,
            result,1,&count,&used)) goto done;
        if(used||count!=truth_count||result[0].id!=truth[0].id) goto done;
        ++rollback;
    }
    printf("META,%zu,%zu,%jd,%zu,%zu\n",hits,(size_t)QUERIES,
           (intmax_t)st.st_size,sizeof s.vectors,rollback);
    samples("SIDE_NS",side_ns);
    samples("EXACT_NS",exact_ns);
    rc=0;
done:
    if(rc) fprintf(stderr,"W12 shadow fixture failed\n");
    qihse_tq_profile_destroy(profile);
    return rc;
}
