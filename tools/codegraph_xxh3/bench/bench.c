/* SPDX-License-Identifier: MIT
 * Resident-buffer benchmark. Calibration, file reads and allocation are untimed.
 */
#define _GNU_SOURCE
#include "qihse_xxh3_inline.h"
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

extern qx3_hash128_t system_hash(const void *,size_t);
extern unsigned system_version(void);
typedef struct { qx3_span *spans; void **allocs; size_t count,cap; uint64_t bytes; } inputs;
typedef enum {CALL,INLINE,BATCH,STREAM,FIXED32} mode;
typedef struct { const char *name; const qx3_backend *b; qx3_hash_fn fn;
                 mode how; uint64_t passes; qx3_stream *stream; } variant;
static volatile uint64_t sink;
static uint64_t rng=UINT64_C(0x86bc25f23476e973);
static uint64_t random64(void) { rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng; }
static void fail(const char *s) { perror(s);exit(1); }
static void invalid(const char *s) { errno=EINVAL;fail(s); }
static uint64_t clock_ns(void)
{
    struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t)) fail("clock");
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static uint64_t number(const char *p)
{
    errno=0;char *end=NULL;unsigned long long n=strtoull(p,&end,10);
    if(errno || !*p || *p=='-' || *end) invalid("invalid argument");
    return (uint64_t)n;
}
static void append(inputs *d,const void *src,size_t n,size_t offset)
{
    if(n>128*1024*1024 || d->bytes+n>256*1024*1024 || d->count>=1000000) invalid("dataset limit");
    if(d->count==d->cap) {
        size_t cap=d->cap?d->cap*2:64;
        qx3_span *sp=realloc(d->spans,cap*sizeof(*sp)); if(!sp) fail("spans");d->spans=sp;
        void **ap=realloc(d->allocs,cap*sizeof(*ap)); if(!ap) fail("allocations");d->allocs=ap;
        d->cap=cap;
    }
    void *base=NULL;int rc=posix_memalign(&base,64,n+128);if(rc){errno=rc;fail("aligned allocation");}
    unsigned char *p=(unsigned char *)base+offset;
    if(src) memcpy(p,src,n); else for(size_t i=0;i<n;++i)p[i]=(unsigned char)random64();
    d->spans[d->count]=(qx3_span){p,n};d->allocs[d->count]=base;++d->count;d->bytes+=n;
}
static void corpus(inputs *d,const char *list,size_t offset)
{
    FILE *f=fopen(list,"r");if(!f)fail("corpus list");
    char *line=NULL;size_t capacity=0;ssize_t got;
    while((got=getline(&line,&capacity,f))>=0) {
        if(got && line[got-1]=='\n') line[--got]='\0';
        if(!got) continue;
        FILE *in=fopen(line,"rb");if(!in)fail(line);
        struct stat st;if(fstat(fileno(in),&st))fail("stat");
        if(!S_ISREG(st.st_mode)||st.st_size<0||st.st_size>128*1024*1024)invalid("corpus file");
        size_t n=(size_t)st.st_size;void *p=malloc(n?n:1);if(!p)fail("corpus memory");
        if(fread(p,1,n,in)!=n || fgetc(in)!=EOF || ferror(in))invalid("corpus changed/read error");
        if(fclose(in))fail("close file");
        append(d,p,n,offset);free(p);
    }
    if(ferror(f))fail("read list");
    free(line);
    if(fclose(f))fail("close list");
    if(!d->count)invalid("empty corpus");
}
static qx3_hash128_t sha256_hash(const void *p,size_t n)
{
    SHA256_CTX ctx;unsigned char out[32];qx3_hash128_t h;
    if(SHA256_Init(&ctx)!=1 || SHA256_Update(&ctx,p,n)!=1 || SHA256_Final(out,&ctx)!=1)abort();
    /* Full 256-bit digest computed; 128 bits consumed only for timing checksum. */
    memcpy(&h.low64,out,8);memcpy(&h.high64,out+8,8);return h;
}
static qx3_hash128_t stream_hash(variant *v,const qx3_span *p)
{
    if(qx3_stream_reset(v->stream,0))abort();
    const unsigned char *data=p->data;
    for(size_t off=0;off<p->size;) {
        size_t n=p->size-off;if(n>65536)n=65536;
        if(qx3_stream_update(v->stream,data+off,n))abort();
        off+=n;
    }
    return qx3_stream_digest(v->stream);
}
static int eq(qx3_hash128_t a,qx3_hash128_t b) { return a.low64==b.low64 && a.high64==b.high64; }
static uint64_t timed(variant *v,const inputs *d,qx3_hash128_t *out,uint64_t *checksum)
{
    uint64_t sum=0,start=clock_ns();
    for(uint64_t pass=0;pass<v->passes;++pass) {
        __asm__ volatile("" ::: "memory"); /* prevent pure-hash loop hoisting */
        if(v->how==BATCH) {
            qx3_batch128(v->b,d->spans,d->count,out);
            for(size_t i=0;i<d->count;++i)sum+=out[i].low64^out[i].high64;
        } else if(v->how==INLINE) {
            for(size_t i=0;i<d->count;++i) {
                qx3_hash128_t h=qx3_hash128_inline(v->b,d->spans[i].data,d->spans[i].size);
                sum+=h.low64^h.high64;
            }
        } else if(v->how==FIXED32) {
            for(size_t i=0;i<d->count;++i) {
                qx3_hash128_t h=qx3_hash128_inline(v->b,d->spans[i].data,32);
                sum+=h.low64^h.high64;
            }
        } else if(v->how==STREAM) {
            for(size_t i=0;i<d->count;++i) {
                qx3_hash128_t h=stream_hash(v,d->spans+i);sum+=h.low64^h.high64;
            }
        } else {
            for(size_t i=0;i<d->count;++i) {
                qx3_hash128_t h=v->fn(d->spans[i].data,d->spans[i].size);sum+=h.low64^h.high64;
            }
        }
    }
    uint64_t elapsed=clock_ns()-start;sink^=sum;*checksum=sum;return elapsed;
}
int main(int argc,char **argv)
{
    size_t size=32,offset=0;unsigned samples=15,ms=8;int cpu=-1;const char *list=NULL;
    for(int i=1;i<argc;++i) {
        const char *key=argv[i];if(++i==argc)invalid("missing value");
        const char *val=argv[i];
        if(!strcmp(key,"--corpus-list")) { list=val;continue; }
        uint64_t n=number(val);
        if(!strcmp(key,"--size")) { if(n>128*1024*1024)invalid("size");size=(size_t)n; }
        else if(!strcmp(key,"--offset")) { if(n>63)invalid("offset");offset=(size_t)n; }
        else if(!strcmp(key,"--samples")) { if(n<1 || n>1000)invalid("samples");samples=(unsigned)n; }
        else if(!strcmp(key,"--ms")) { if(n<1 || n>1000)invalid("ms");ms=(unsigned)n; }
        else if(!strcmp(key,"--cpu")) { if(n>=CPU_SETSIZE)invalid("cpu");cpu=(int)n; }
        else invalid("unknown option");
    }
    cpu_set_t allowed,selected;if(sched_getaffinity(0,sizeof(allowed),&allowed))fail("affinity");
    if(cpu<0)for(int i=0;i<CPU_SETSIZE;++i)if(CPU_ISSET(i,&allowed)){cpu=i;break;}
    if(cpu<0 || !CPU_ISSET(cpu,&allowed))invalid("CPU not allowed");
    CPU_ZERO(&selected);CPU_SET(cpu,&selected);
    if(sched_setaffinity(0,sizeof(selected),&selected))fail("pin CPU");
    inputs d={0};
    if(list)corpus(&d,list,offset);
    else {
        size_t count=size?1048576/size:4096;if(count<1)count=1;if(count>4096)count=4096;
        for(size_t i=0;i<count;++i)append(&d,NULL,size,offset);
    }
    qx3_hash128_t *out=malloc(d.count*sizeof(*out));if(!out)fail("output");
    variant variants[12];size_t count=0;
    const char *names[]={"scalar","sse2","avx2","avx512"};
    const char *labels[]={"xxh3_scalar","xxh3_sse2","xxh3_avx2","xxh3_avx512"};
    for(unsigned i=0;i<4;++i) {
        const qx3_backend *b=qx3_backend_get(names[i]);
        if(b)variants[count++]=(variant){labels[i],b,b->hash128,CALL,1,NULL};
    }
    const qx3_backend *auto_b=qx3_backend_get("auto");
    variants[count++]=(variant){"xxh3_auto_inline",auto_b,NULL,INLINE,1,NULL};
    variants[count++]=(variant){"xxh3_auto_batch",auto_b,NULL,BATCH,1,NULL};
    qx3_stream *stream=qx3_stream_create(auto_b,0);if(!stream)fail("stream");
    variants[count++]=(variant){"xxh3_auto_stream64k",auto_b,NULL,STREAM,1,stream};
    variants[count++]=(variant){"xxh3_shared",NULL,system_hash,CALL,1,NULL};
    variants[count++]=(variant){"sha256_direct",NULL,sha256_hash,CALL,1,NULL};
    if(!list && size==32)variants[count++]=(variant){"xxh3_inline_fixed32",auto_b,NULL,FIXED32,1,NULL};
    for(size_t v=0;v<count;++v) {
        variant *c=variants+v;
        if(!strcmp(c->name,"sha256_direct"))continue;
        if(c->how==BATCH)qx3_batch128(c->b,d.spans,d.count,out);
        for(size_t i=0;i<d.count;++i) {
            qx3_span p=d.spans[i];qx3_hash128_t expected=system_hash(p.data,p.size),actual;
            if(c->how==CALL)actual=c->fn(p.data,p.size);
            else if(c->how==BATCH)actual=out[i];
            else if(c->how==STREAM)actual=stream_hash(c,&p);
            else if(c->how==FIXED32)actual=qx3_hash128_inline(c->b,p.data,32);
            else actual=qx3_hash128_inline(c->b,p.data,p.size);
            if(!eq(expected,actual)) { fprintf(stderr,"Mismatch: %s record %zu\n",c->name,i);return 1; }
        }
    }
    uint64_t checksum=0;
    for(size_t v=0;v<count;++v) {
        variant *c=variants+v;uint64_t elapsed;
        for(;;) { elapsed=timed(c,&d,out,&checksum);if(elapsed>=1000000)break;c->passes*=2; }
        long double want=(long double)c->passes*(ms*1000000.0L)/elapsed;
        c->passes=(uint64_t)want;if(!c->passes)c->passes=1;
    }
    printf("{\"metadata\":{\"cpu\":%d,\"clock\":\"CLOCK_MONOTONIC_RAW\",\"auto_backend\":\"%s\","
           "\"records\":%zu,\"input_bytes\":%"PRIu64",\"offset\":%zu,\"xxhash_version\":%u,"
           "\"openssl\":\"%s\",\"samples\":%u,\"target_ms\":%u},\"samples\":[\n",
           cpu,auto_b->name,d.count,d.bytes,offset,system_version(),OpenSSL_version(OPENSSL_VERSION),samples,ms);
    int first=1;
    for(unsigned round=0;round<samples;++round) {
        size_t order[12];for(size_t i=0;i<count;++i)order[i]=i;
        for(size_t i=count;i>1;--i) { size_t j=random64()%i,t=order[i-1];order[i-1]=order[j];order[j]=t; }
        for(size_t i=0;i<count;++i) {
            variant *c=variants+order[i];uint64_t elapsed=timed(c,&d,out,&checksum);
            printf("%s{\"candidate\":\"%s\",\"round\":%u,\"order\":%zu,\"passes\":%"PRIu64
                   ",\"calls\":%"PRIu64",\"bytes\":%"PRIu64",\"ns\":%"PRIu64",\"checksum\":\"%016"PRIx64"\"}\n",
                   first?"":",",c->name,round,i,c->passes,c->passes*d.count,c->passes*d.bytes,elapsed,checksum);first=0;
        }
    }
    puts("]}");qx3_stream_free(stream);free(out);
    for(size_t i=0;i<d.count;++i)free(d.allocs[i]);
    free(d.allocs);free(d.spans);
    return 0;
}
