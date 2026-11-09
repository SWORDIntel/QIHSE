/* Standalone W12.2 derived QTQS prototype; no production VectorDB wiring. */
#define _POSIX_C_SOURCE 200809L
#include "qihse_turboquant_sidecar.h"
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HEADER_BYTES 64u
#define ROW_HEADER_BYTES 16u
#define ROW_CRC_BYTES 4u
#define PROFILE_MAX_BYTES (64u + (2u*1536u*1536u+16u)*8u)
#define FILE_MAX_BYTES (PROFILE_MAX_BYTES + 64u + 100000u*(20u+1024u))

static void p16(uint8_t *p, uint16_t x) { p[0]=(uint8_t)x; p[1]=(uint8_t)(x>>8); }
static void p32(uint8_t *p, uint32_t x) { unsigned i; for(i=0;i<4;i++) p[i]=(uint8_t)(x>>(8*i)); }
static void p64(uint8_t *p, uint64_t x) { unsigned i; for(i=0;i<8;i++) p[i]=(uint8_t)(x>>(8*i)); }
static uint16_t g16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0]|((uint16_t)p[1]<<8)); }
static uint32_t g32(const uint8_t *p) { unsigned i; uint32_t x=0; for(i=0;i<4;i++) x|=(uint32_t)p[i]<<(8*i); return x; }
static uint64_t g64(const uint8_t *p) { unsigned i; uint64_t x=0; for(i=0;i<8;i++) x|=(uint64_t)p[i]<<(8*i); return x; }
static uint32_t crc(const uint8_t *p, size_t n) {
    uint32_t x=UINT32_MAX; size_t i; unsigned j;
    for(i=0;i<n;i++) { x^=p[i]; for(j=0;j<8;j++) x=(x>>1)^((0u-(x&1u))&UINT32_C(0xedb88320)); }
    return ~x;
}
static int wr(int fd, const void *data, size_t n) {
    const uint8_t *p=data;
    while(n) { ssize_t v=write(fd,p,n); if(v<0 && errno==EINTR) continue;
        if(v<=0) return errno?errno:EIO;
        p+=(size_t)v; n-=(size_t)v; }
    return 0;
}
static int rd(int fd, void *data, size_t n) {
    uint8_t *p=data;
    while(n) { ssize_t v=read(fd,p,n); if(v<0 && errno==EINTR) continue;
        if(v<=0) return v==0?EBADMSG:errno;
        p+=(size_t)v; n-=(size_t)v; }
    return 0;
}
static int skip(int fd, size_t n) {
    return lseek(fd,(off_t)n,SEEK_CUR)<0?errno:0;
}
static int sync_parent(const char *path) {
    const char *slash=strrchr(path,'/'); size_t n=slash?(size_t)(slash-path):1u;
    char *dir=malloc(n+1); int fd,rc;
    if(!dir) return ENOMEM;
    if(slash) { if(!n) { dir[0]='/'; n=1; } else memcpy(dir,path,n); }
    else dir[0]='.';
    dir[n]=0;
    fd=open(dir,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    free(dir);
    if(fd<0) return errno;
    rc=fsync(fd)<0?errno:0; close(fd); return rc;
}
static int profile_image(const qihse_tq_profile *profile, uint8_t **out,
                         size_t *size, size_t *code_size, size_t *dims) {
    qihse_tq_config c={0}; uint8_t *image; int rc;
    if(!profile||!out||!size||!code_size||!dims) return EINVAL;
    rc=qihse_tq_profile_serialized_size(profile,size); if(rc) return rc;
    if(*size>PROFILE_MAX_BYTES) return EOVERFLOW;
    image=malloc(*size); if(!image) return ENOMEM;
    rc=qihse_tq_profile_serialize(profile,image,*size);
    if(rc) { free(image); return rc; }
    c.dimensions=g32(image+8); c.scalar_bits=g32(image+12);
    c.variant=(qihse_tq_variant)g32(image+16);
    c.rotation_seed=g64(image+24); c.projection_seed=g64(image+32);
    rc=qihse_tq_code_size(&c,code_size);
    if(rc) { free(image); return rc; }
    *dims=c.dimensions; *out=image; return 0;
}
static int header(int fd, uint64_t generation, uint32_t *rows,
                  uint32_t *dimensions, uint32_t *code_size,
                  uint32_t *profile_size) {
    uint8_t h[HEADER_BYTES]; struct stat st; uint64_t total;
    if(fstat(fd,&st)<0) return errno;
    if(!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0077)!=0||
       st.st_size<(off_t)HEADER_BYTES||
       (uint64_t)st.st_size>FILE_MAX_BYTES) return EBADMSG;
    if(rd(fd,h,sizeof h)) return EBADMSG;
    if(memcmp(h,"QTQS",4)||g32(h+4)!=QIHSE_TQ_SIDECAR_VERSION||
       g32(h+40)!=crc(h,40)||g32(h+44)!=0||g64(h+48)!=0||g64(h+56)!=0)
        return EBADMSG;
    if(g64(h+8)!=generation) return ESTALE;
    *rows=g32(h+16); *dimensions=g32(h+20);
    *code_size=g32(h+24); *profile_size=g32(h+28);
    total=g64(h+32);
    if(*rows>QIHSE_TQ_SIDECAR_MAX_ROWS||*dimensions<2||
       *dimensions>QIHSE_TQ_MAX_DIMENSIONS||*code_size<64||
       *code_size>1024||*profile_size<64||*profile_size>PROFILE_MAX_BYTES||
       total!=(uint64_t)HEADER_BYTES+*profile_size+
             (uint64_t)*rows*(ROW_HEADER_BYTES+*code_size+ROW_CRC_BYTES)||
       total!=(uint64_t)st.st_size) return EBADMSG;
    return 0;
}
static int open_read(const char *path) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) return -1;
    return fd;
}
static int borrow_user(const qihse_user_t *presented, qihse_user_t **borrowed,
                       uint64_t *generation) {
    uint32_t id;
    if(!presented||!borrowed||!generation) return EACCES;
    id=qihse_user_get_id(presented);
    if(id==UINT32_MAX) return EACCES;
    *borrowed=qihse_auth_borrow_principal_scoped(id,generation);
    if(*borrowed!=presented||!*generation) {
        qihse_auth_release_principal_scoped(*borrowed);
        *borrowed=NULL;
        return EACCES;
    }
    return 0;
}

int qihse_tq_sidecar_publish(const char *path, const qihse_user_t *actor,
                             const qihse_tq_profile *profile,
                             uint64_t generation,
                             const qihse_tq_sidecar_row *rows, size_t count) {
    uint8_t *image=NULL,*code=NULL,*record=NULL; size_t profile_bytes=0,code_bytes=0,dims=0;
    uint8_t h[HEADER_BYTES]; char *tmp=NULL; int fd=-1,rc=EINVAL; size_t i;
    uint64_t previous=0,total;
    uint64_t actor_generation=0; qihse_user_t *borrowed=NULL;
    if(!path||!*path||!generation||count>QIHSE_TQ_SIDECAR_MAX_ROWS||
       (count&&!rows)) return EINVAL;
    rc=borrow_user(actor,&borrowed,&actor_generation); if(rc) return rc;
    rc=profile_image(profile,&image,&profile_bytes,&code_bytes,&dims); if(rc) goto done;
    if(code_bytes>1024) { rc=EOVERFLOW; goto done; }
    total=HEADER_BYTES+profile_bytes+count*(ROW_HEADER_BYTES+code_bytes+ROW_CRC_BYTES);
    if(total>FILE_MAX_BYTES) { rc=EOVERFLOW; goto done; }
    for(i=0;i<count;i++) {
        if(!rows[i].id||rows[i].id<=previous||!rows[i].vector) { rc=EINVAL; goto done; }
        if(!qihse_auth_can_access(borrowed,rows[i].classification,rows[i].sci)) {
            rc=EACCES; goto done;
        }
        previous=rows[i].id;
    }
    code=malloc(code_bytes); record=malloc(ROW_HEADER_BYTES+code_bytes);
    tmp=malloc(strlen(path)+16);
    if(!code||!record||!tmp) { rc=ENOMEM; goto done; }
    sprintf(tmp,"%s.tmp.XXXXXX",path);
    fd=mkstemp(tmp); if(fd<0) { rc=errno; goto done; }
    if(fchmod(fd,0600)<0) { rc=errno; goto done; }
    memset(h,0,sizeof h); memcpy(h,"QTQS",4);
    p32(h+4,QIHSE_TQ_SIDECAR_VERSION); p64(h+8,generation);
    p32(h+16,(uint32_t)count); p32(h+20,(uint32_t)dims);
    p32(h+24,(uint32_t)code_bytes); p32(h+28,(uint32_t)profile_bytes);
    p64(h+32,total); p32(h+40,crc(h,40));
    if((rc=wr(fd,h,sizeof h))||(rc=wr(fd,image,profile_bytes))) goto done;
    for(i=0;i<count;i++) {
        rc=qihse_tq_encode(profile,rows[i].vector,dims,code,code_bytes);
        if(rc) goto done;
        memset(record,0,ROW_HEADER_BYTES);
        p64(record,rows[i].id); p16(record+8,rows[i].classification); p16(record+10,rows[i].sci);
        memcpy(record+ROW_HEADER_BYTES,code,code_bytes);
        p32(h,crc(record,ROW_HEADER_BYTES+code_bytes));
        if((rc=wr(fd,record,ROW_HEADER_BYTES+code_bytes))||(rc=wr(fd,h,4))) goto done;
    }
    if(fsync(fd)<0) { rc=errno; goto done; }
    if(close(fd)<0) { fd=-1; rc=errno; goto done; } fd=-1;
    if(!qihse_auth_validate_handle_generation(borrowed,actor_generation)) {
        rc=EACCES; goto done;
    }
    if(rename(tmp,path)<0) { rc=errno; goto done; }
    rc=sync_parent(path);
done:
    if(fd>=0) close(fd);
    if(rc&&tmp) unlink(tmp);
    free(tmp); free(code); free(record); free(image);
    qihse_auth_release_principal_scoped(borrowed);
    return rc;
}

int qihse_tq_sidecar_open_profile(const char *path,const qihse_user_t *user,
                                  uint64_t generation,qihse_tq_profile **out) {
    uint32_t rows,dims,code_bytes,profile_bytes;
    qihse_tq_profile *p=NULL; uint8_t *image=NULL; int fd,rc;
    uint64_t user_generation=0; qihse_user_t *borrowed=NULL;
    if(!out) return EINVAL;
    *out=NULL;
    if(!path||!generation) return EINVAL;
    rc=borrow_user(user,&borrowed,&user_generation); if(rc) return rc;
    fd=open_read(path); if(fd<0) { rc=errno; goto done; }
    rc=header(fd,generation,&rows,&dims,&code_bytes,&profile_bytes);
    if(rc) goto done;
    image=malloc(profile_bytes); if(!image) { rc=ENOMEM; goto done; }
    rc=rd(fd,image,profile_bytes); if(rc) goto done;
    rc=qihse_tq_profile_deserialize(image,profile_bytes,&p);
    if(rc) goto done;
    /* Profile's own config must match the sidecar outer envelope. */
    { uint8_t *check=NULL; size_t n=0,c=0,d=0;
      rc=profile_image(p,&check,&n,&c,&d); free(check);
      if(rc||n!=profile_bytes||c!=code_bytes||d!=dims) { rc=EBADMSG; goto done; }
    }
    if(!qihse_auth_validate_handle_generation(borrowed,user_generation)) {
        rc=EACCES; goto done;
    }
    *out=p; p=NULL; rc=0;
done:
    free(image); qihse_tq_profile_destroy(p);
    if(fd>=0) close(fd);
    qihse_auth_release_principal_scoped(borrowed);
    return rc;
}

static int better(qihse_tq_metric metric,double a,uint64_t aid,double b,uint64_t bid) {
    return metric==QIHSE_TQ_L2_SQUARED?(a<b||(a==b&&aid<bid)):
        (a>b||(a==b&&aid<bid));
}
typedef int (*predicate_fn)(const qihse_user_t *,uint64_t,void *);
static int candidates(const char *path,const qihse_user_t *user,uint64_t generation,
                      const qihse_tq_profile *profile,const float *query,size_t dims,
                      qihse_tq_metric metric,predicate_fn visible,void *opaque,
                      qihse_tq_candidate *out,size_t capacity,size_t *count) {
    uint32_t rows,hdims,code_bytes,profile_bytes; size_t want=0,csize=0,pdims=0,i,n=0;
    uint8_t *expected=NULL,*actual=NULL,*record=NULL,word[4],rh[ROW_HEADER_BYTES];
    qihse_tq_query *prepared=NULL; uint64_t previous=0; int fd=-1,rc;
    fd=open_read(path); if(fd<0) return errno;
    rc=header(fd,generation,&rows,&hdims,&code_bytes,&profile_bytes); if(rc) goto done;
    rc=profile_image(profile,&expected,&want,&csize,&pdims); if(rc) goto done;
    if(want!=profile_bytes||csize!=code_bytes||pdims!=hdims||dims!=hdims) {
        rc=EBADMSG; goto done;
    }
    actual=malloc(profile_bytes); record=malloc(ROW_HEADER_BYTES+code_bytes);
    if(!actual||!record) { rc=ENOMEM; goto done; }
    rc=rd(fd,actual,profile_bytes); if(rc) goto done;
    if(memcmp(expected,actual,profile_bytes)) { rc=EBADMSG; goto done; }
    rc=qihse_tq_prepare_query(profile,query,dims,&prepared); if(rc) goto done;
    for(i=0;i<rows;i++) {
        uint64_t id; uint16_t classif,sci; double score; size_t j;
        rc=rd(fd,rh,sizeof rh); if(rc) goto done;
        id=g64(rh); classif=g16(rh+8); sci=g16(rh+10);
        if(!id||id<=previous||g32(rh+12)!=0) { rc=EBADMSG; goto done; }
        previous=id;
        if(!qihse_auth_user_is_active(user)) { rc=EACCES; goto done; }
        if(!qihse_auth_can_access(user,classif,sci)) {
            rc=skip(fd,code_bytes+4u); if(rc) goto done; continue;
        }
        rc=visible(user,id,opaque);
        if(rc==EACCES) {
            rc=skip(fd,code_bytes+4u); if(rc) goto done; continue;
        }
        if(rc) goto done;
        memcpy(record,rh,sizeof rh);
        rc=rd(fd,record+ROW_HEADER_BYTES,code_bytes); if(rc) goto done;
        rc=rd(fd,word,4); if(rc) goto done;
        if(crc(record,ROW_HEADER_BYTES+code_bytes)!=g32(word)) { rc=EBADMSG; goto done; }
        rc=qihse_tq_score(profile,prepared,record+ROW_HEADER_BYTES,code_bytes,metric,&score);
        if(rc||!isfinite(score)) { rc=EBADMSG; goto done; }
        for(j=0;j<n;j++) if(better(metric,score,id,out[j].estimate,out[j].id)) break;
        if(j<capacity) {
            size_t end=n<capacity?n:capacity-1u;
            while(end>j) { out[end]=out[end-1u]; --end; }
            out[j].id=id; out[j].estimate=score;
            if(n<capacity) ++n;
        }
    }
    { struct stat st; off_t position=lseek(fd,0,SEEK_CUR);
      if(position<0||fstat(fd,&st)<0||position!=st.st_size) {
          rc=EBADMSG; goto done;
      }
    }
    if(!qihse_auth_user_is_active(user)) { rc=EACCES; goto done; }
    *count=n; rc=0;
done:
    free(expected); free(actual); free(record);
    qihse_tq_query_destroy(prepared); close(fd); return rc;
}
typedef struct {
    qihse_tq_live_visible_fn visible;
    void *opaque;
} legacy_visible_context;
static int legacy_visible(const qihse_user_t *user,uint64_t id,void *opaque) {
    legacy_visible_context *ctx=opaque;
    return ctx->visible(user,id,ctx->opaque)?0:EACCES;
}
int qihse_tq_sidecar_candidates_or_exact(
    const char *path,const qihse_user_t *user,uint64_t generation,
    const qihse_tq_profile *profile,const float *query,size_t dims,
    qihse_tq_metric metric,qihse_tq_live_visible_fn visible,
    qihse_tq_exact_fallback_fn fallback,void *opaque,
    qihse_tq_candidate *out,size_t capacity,size_t *out_count,bool *used_sidecar) {
    qihse_tq_candidate *scratch; size_t n=0; int rc; bool used=false;
    qihse_user_t *borrowed=NULL; uint64_t user_generation=0;
    legacy_visible_context ctx={visible,opaque};
    if(!path||!generation||!profile||
       !query||!visible||!fallback||!out||!out_count||!used_sidecar||
       capacity==0||capacity>QIHSE_TQ_SIDECAR_MAX_ROWS||
       metric<QIHSE_TQ_DOT||metric>QIHSE_TQ_L2_SQUARED) return EINVAL;
    rc=borrow_user(user,&borrowed,&user_generation); if(rc) return rc;
    scratch=calloc(capacity,sizeof *scratch);
    if(!scratch) { qihse_auth_release_principal_scoped(borrowed); return ENOMEM; }
    rc=candidates(path,borrowed,generation,profile,query,dims,metric,legacy_visible,&ctx,
                  scratch,capacity,&n);
    if(rc==ENOENT||rc==ESTALE||rc==EBADMSG||rc==EIO) {
        n=0; rc=fallback(borrowed,query,dims,metric,scratch,capacity,&n,opaque);
        if(!rc&&n>capacity) rc=EOVERFLOW;
    } else if(!rc) used=true;
    if(!rc&&!qihse_auth_validate_handle_generation(borrowed,user_generation))
        rc=EACCES;
    if(!rc) {
        memcpy(out,scratch,n*sizeof *out);
        *out_count=n; *used_sidecar=used;
    }
    free(scratch);
    qihse_auth_release_principal_scoped(borrowed);
    return rc;
}

typedef struct {
    qihse_tq_scoped_visible_fn visible;
    qihse_tq_scope scope;
    uint64_t source_generation;
    void *opaque;
    bool source_stale;
} scoped_visible_context;
static int scoped_visible(const qihse_user_t *user,uint64_t id,void *opaque) {
    scoped_visible_context *ctx=opaque;
    int rc=ctx->visible(user,id,ctx->scope,ctx->source_generation,ctx->opaque);
    if(rc==ESTALE) ctx->source_stale=true;
    return rc;
}
int qihse_tq_sidecar_search_scoped(
    const char *path,const qihse_user_t *user,qihse_tq_scope scope,
    uint64_t source_generation,const qihse_tq_profile *profile,
    const float *query,size_t dims,qihse_tq_metric metric,
    size_t candidate_pool,qihse_tq_scoped_visible_fn live_visible,
    qihse_tq_scoped_score_fn exact_score,
    qihse_tq_scoped_exact_fn exact_fallback,void *opaque,
    qihse_tq_candidate *out,size_t top_k,size_t *out_count,bool *used_sidecar) {
    qihse_tq_candidate *pool=NULL,*ranked=NULL;
    qihse_user_t *borrowed=NULL;
    scoped_visible_context visible_ctx={live_visible,scope,source_generation,opaque,false};
    uint64_t principal_generation=0;
    size_t pool_count=0,n=0,i,j;
    int rc; bool used=false,fallback=false;
    if(!path||!source_generation||!profile||!query||!live_visible||
       !exact_score||!exact_fallback||!out||!out_count||!used_sidecar||
       dims<2||dims>QIHSE_TQ_MAX_DIMENSIONS||
       !top_k||top_k>candidate_pool||candidate_pool>QIHSE_TQ_SIDECAR_MAX_ROWS||
       metric<QIHSE_TQ_DOT||metric>QIHSE_TQ_L2_SQUARED) return EINVAL;
    for(i=0;i<dims;i++) if(!isfinite(query[i])) return EINVAL;
    rc=borrow_user(user,&borrowed,&principal_generation); if(rc) return rc;
    pool=calloc(candidate_pool,sizeof *pool);
    ranked=calloc(top_k,sizeof *ranked);
    if(!pool||!ranked) { rc=ENOMEM; goto done; }
    rc=candidates(path,borrowed,source_generation,profile,query,dims,metric,
                  scoped_visible,&visible_ctx,pool,candidate_pool,&pool_count);
    if(visible_ctx.source_stale) { rc=ESTALE; goto done; }
    if(rc==ENOENT||rc==ESTALE||rc==EBADMSG||rc==EIO) {
        fallback=true;
    } else if(rc) goto done;
    if(!fallback) for(i=0;i<pool_count;i++) {
        double score=0;
        rc=exact_score(borrowed,pool[i].id,scope,source_generation,
                       query,dims,metric,&score,opaque);
        if(rc==EACCES) { fallback=true; break; }
        if(rc) goto done;
        if(!isfinite(score)) { rc=EBADMSG; goto done; }
        for(j=0;j<n;j++)
            if(better(metric,score,pool[i].id,ranked[j].estimate,ranked[j].id))
                break;
        if(j<top_k) {
            size_t end=n<top_k?n:top_k-1u;
            while(end>j) { ranked[end]=ranked[end-1u]; --end; }
            ranked[j].id=pool[i].id; ranked[j].estimate=score;
            if(n<top_k) ++n;
        }
    }
    if(fallback) {
        n=0;
        rc=exact_fallback(borrowed,scope,source_generation,query,dims,metric,
                          ranked,top_k,&n,opaque);
        if(rc) goto done;
        if(n>top_k) { rc=EOVERFLOW; goto done; }
    } else used=true;
    if(!qihse_auth_validate_handle_generation(borrowed,principal_generation)) {
        rc=EACCES; goto done;
    }
    memcpy(out,ranked,n*sizeof *out);
    *out_count=n; *used_sidecar=used; rc=0;
done:
    free(pool); free(ranked);
    qihse_auth_release_principal_scoped(borrowed);
    return rc;
}
