/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "qihse_xxh3_inline.h"
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static uint64_t checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while(0)
static int equal(qx3_hash128_t a, qx3_hash128_t b)
{ return a.low64==b.low64 && a.high64==b.high64; }
static const qx3_backend *reference_backend;
#ifdef QX3_SYSTEM_ORACLE
extern qx3_hash128_t system_seed(const void *,size_t,uint64_t);
extern void system_canonical(qx3_hash128_t,unsigned char[16]);
extern unsigned system_version(void);
#endif
static qx3_hash128_t ref(const void *p,size_t n,uint64_t seed)
{
#ifdef QX3_SYSTEM_ORACLE
    return system_seed(p,n,seed);
#else
    return qx3_hash128_seed(reference_backend,p,n,seed);
#endif
}
static void one(const qx3_backend *b,const void *p,size_t n,uint64_t seed)
{
    qx3_hash128_t expected=ref(p,n,seed);
    CHECK(equal(expected,qx3_hash128_seed(b,p,n,seed)));
    CHECK(equal(expected,qx3_hash128_seed_inline(b,p,n,seed)));
    if (seed==0) {
        CHECK(equal(expected,qx3_hash128(b,p,n)));
        CHECK(equal(expected,qx3_hash128_inline(b,p,n)));
    }
    unsigned char a[16],c[16]; qx3_canonical(expected,a);
#ifdef QX3_SYSTEM_ORACLE
    system_canonical(expected,c);
#else
    for (unsigned i=0;i<8;++i) {
        c[i]=(unsigned char)(expected.high64>>(56-8*i));
        c[i+8]=(unsigned char)(expected.low64>>(56-8*i));
    }
#endif
    CHECK(!memcmp(a,c,16));
}
static void streaming(const qx3_backend *b,const unsigned char *p)
{
    static const size_t lengths[]={0,1,16,32,63,64,65,128,239,240,241,255,256,257,1023,1024,1025,4096,65536,65537};
    static const size_t chunks[]={1,3,63,64,65,239,240,241,1024,4096,65536};
    static const uint64_t seeds[]={0,1,UINT64_C(0x1234567890abcdef),UINT64_MAX};
    qx3_stream *s=qx3_stream_create(b,0); CHECK(s);
    for(size_t x=0;x<sizeof(lengths)/sizeof(lengths[0]);++x)
    for(size_t z=0;z<sizeof(seeds)/sizeof(seeds[0]);++z)
    for(size_t k=0;k<sizeof(chunks)/sizeof(chunks[0]);++k) {
        size_t n=lengths[x]; uint64_t seed=seeds[z];
        CHECK(!qx3_stream_reset(s,seed));
        CHECK(!qx3_stream_update(s,NULL,0));
        for(size_t off=0;off<n;) {
            size_t take=n-off; if(take>chunks[k]) take=chunks[k];
            CHECK(!qx3_stream_update(s,p+off,take)); off+=take;
        }
        CHECK(equal(qx3_stream_digest(s),ref(p,n,seed)));
        /* Digest is non-destructive; update again after digest. */
        CHECK(!qx3_stream_update(s,p+n,1));
        CHECK(equal(qx3_stream_digest(s),ref(p,n+1,seed)));
    }
    qx3_hash128_t before=qx3_stream_digest(s);
    errno=0; CHECK(qx3_stream_update(s,NULL,1)==-1 && errno==EINVAL);
    CHECK(equal(before,qx3_stream_digest(s)));
    qx3_stream_free(s);
}
static void guard(const qx3_backend *b)
{
    long ps=sysconf(_SC_PAGESIZE); CHECK(ps>0);
    unsigned char *p=mmap(NULL,(size_t)ps*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(p!=MAP_FAILED); CHECK(!mprotect(p+ps,(size_t)ps,PROT_READ|PROT_WRITE));
    for(long i=0;i<ps;++i) p[ps+i]=(unsigned char)(i*11+7);
    for(size_t n=0;n<=(size_t)ps;++n) {
        one(b,p+2*ps-n,n,0); one(b,p+ps,n,UINT64_C(0xdeadbeef));
    }
    CHECK(!munmap(p,(size_t)ps*3));
}
typedef struct { const qx3_backend *b; const unsigned char *p; int failed; } thread_arg;
static void *worker(void *arg)
{
    thread_arg *a=arg;
    qx3_stream *s=qx3_stream_create(a->b,0);
    if(!s) { a->failed=1; return NULL; }
    for(size_t i=0;i<1000;++i) {
        uint64_t seed=i*UINT64_C(0x9e3779b185ebca87);
        if(qx3_stream_reset(s,seed) || qx3_stream_update(s,a->p,i) ||
           !equal(qx3_stream_digest(s),ref(a->p,i,seed))) { a->failed=1; break; }
    }
    qx3_stream_free(s); return NULL;
}
static const qx3_backend *batch_delegate;
static unsigned batch_calls;
static void counted_batch(const void *blob, const size_t *offsets, size_t count,
                          unsigned char *out)
{
    ++batch_calls;
    batch_delegate->_canonical_batch(blob, offsets, count, out);
}
static void canonical_adapters(const qx3_backend *b, const unsigned char *buf)
{
    unsigned char out[16*17], expected[16], guard[sizeof(out)];
    size_t offsets[18]; offsets[0] = 0;
    for (size_t i=0;i<17;++i) offsets[i+1]=offsets[i]+i*i;
    CHECK(!qx3_batch_canonical128(b, NULL, 0, NULL, 0, NULL));
    CHECK(!qx3_hash_canonical128(b, NULL, 0, out));
    qx3_canonical(ref(NULL,0,0),expected); CHECK(!memcmp(out,expected,16));
    unsigned char unaligned[32];
    for (size_t off=0;off<16;++off) {
        qx3_canonical(ref(NULL,0,0),unaligned+off);
        CHECK(!memcmp(unaligned+off,expected,16));
    }
    CHECK(!qx3_batch_canonical128(b,buf,offsets[17],offsets,17,out));
    for(size_t i=0;i<17;++i) {
        qx3_canonical(ref(buf+offsets[i],offsets[i+1]-offsets[i],0),expected);
        CHECK(!memcmp(out+16*i,expected,16));
        CHECK(!qx3_hash_canonical128(b,buf+offsets[i],offsets[i+1]-offsets[i],out+16*i));
        CHECK(!memcmp(out+16*i,expected,16));
    }
    qx3_backend counted=*b; counted._canonical_batch=counted_batch;
    batch_delegate=b; batch_calls=0;
    CHECK(!qx3_batch_canonical128(&counted,buf,offsets[17],offsets,17,out));
    CHECK(batch_calls==1);
    memset(out,0xa5,sizeof(out));memcpy(guard,out,sizeof(out));
    CHECK(qx3_batch_canonical128(NULL,buf,offsets[17],offsets,17,out)==-1);
    CHECK(qx3_batch_canonical128(b,NULL,1,offsets,17,out)==-1);
    CHECK(qx3_batch_canonical128(b,buf,offsets[17],offsets,SIZE_MAX,out)==-1 && errno==EOVERFLOW);
    CHECK(qx3_batch_canonical128(b,buf,offsets[17],NULL,17,out)==-1);
    CHECK(qx3_batch_canonical128(b,buf,offsets[17],offsets,17,NULL)==-1);
    offsets[0]=1;CHECK(qx3_batch_canonical128(b,buf,offsets[17],offsets,17,out)==-1);offsets[0]=0;
    offsets[4]=offsets[5]+1;CHECK(qx3_batch_canonical128(b,buf,offsets[17],offsets,17,out)==-1);offsets[4]=14;
    CHECK(qx3_batch_canonical128(b,buf,offsets[17]-1,offsets,17,out)==-1);
    CHECK(qx3_batch_canonical128(b,buf,1,NULL,0,NULL)==-1);
    CHECK(qx3_hash_canonical128(b,NULL,1,out)==-1);
    CHECK(qx3_hash_canonical128(b,out,1,out)==-1);
    CHECK(qx3_batch_canonical128(b,out,sizeof(out),offsets,17,out)==-1);
    size_t overlap[3]={0,0,0};
    CHECK(qx3_batch_canonical128(b,NULL,0,overlap,1,(unsigned char*)overlap)==-1);
    CHECK(!memcmp(out,guard,sizeof(out)));
    /* Zero-length records with NULL storage still have ordinary empty digests. */
    size_t empty[]={0,0,0};
    CHECK(!qx3_batch_canonical128(b,NULL,0,empty,2,out));
    qx3_canonical(ref(NULL,0,0),expected);
    CHECK(!memcmp(out,expected,16) && !memcmp(out+16,expected,16));
}
int main(void)
{
    reference_backend=qx3_backend_get("scalar"); CHECK(reference_backend);
    errno=0; CHECK(!qx3_backend_get("not-a-backend") && errno==EINVAL);
    CHECK(qx3_backend_get(NULL)); CHECK(!qx3_stream_create(NULL,0));
    CHECK(qx3_stream_reset(NULL,0)==-1); CHECK(qx3_stream_update(NULL,NULL,0)==-1);
    qx3_stream_free(NULL);
    errno=0; qx3_hash128_t null_digest=qx3_stream_digest(NULL);
    CHECK(errno==EINVAL && !null_digest.low64 && !null_digest.high64);
    unsigned char *buf=malloc(131072+128); CHECK(buf);
    uint64_t rng=UINT64_C(0xfedcba0987654321);
    for(size_t i=0;i<131072+128;++i) { rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;buf[i]=(unsigned char)rng; }
    const char *names[]={"scalar","sse2","avx2","avx512","auto"};
    for(unsigned k=0;k<5;++k) {
        const qx3_backend *b=qx3_backend_get(names[k]);
        if(!b) { CHECK(errno==ENOTSUP); printf("SKIP %s (unavailable)\n",names[k]); continue; }
        printf("TEST %s -> %s\n",names[k],b->name);
        char hex[33]; qx3_hex(qx3_hash128(b,NULL,0),hex);
        CHECK(!strcmp(hex,"99aa06d3014798d86001c324468d497f"));
        qx3_hex(qx3_hash128(b,"abc",3),hex);
        CHECK(!strcmp(hex,"06b05ab6733a618578af5f94892f3950"));
        one(b,NULL,0,0); one(b,NULL,0,UINT64_MAX);
        for(size_t n=0;n<=2048;++n)
            for(size_t off=0;off<16;++off) { one(b,buf+off,n,0); one(b,buf+off,n,UINT64_MAX); }
        static const size_t edges[]={4095,4096,4097,8191,8192,16383,16384,65535,65536,65537};
        for(size_t j=0;j<sizeof(edges)/sizeof(edges[0]);++j)
            for(size_t off=0;off<64;++off) one(b,buf+off,edges[j],UINT64_C(0x123456789abcdef0));
        qx3_batch128(b,NULL,0,NULL);
        qx3_span spans[259]; qx3_hash128_t out[259];
        for(size_t i=0;i<259;++i) spans[i]=(qx3_span){buf+i%64,i*i%65537};
        spans[0]=(qx3_span){NULL,0};
        static const size_t counts[]={1,2,3,4,5,31,257,259};
        for(size_t j=0;j<sizeof(counts)/sizeof(counts[0]);++j) {
            qx3_batch128(b,spans,counts[j],out);
            for(size_t i=0;i<counts[j];++i) CHECK(equal(out[i],ref(spans[i].data,spans[i].size,0)));
        }
        canonical_adapters(b,buf);
        streaming(b,buf+1); guard(b);
        pthread_t threads[4]; thread_arg args[4];
        for(unsigned i=0;i<4;++i) { args[i]=(thread_arg){b,buf+i,0}; CHECK(!pthread_create(threads+i,NULL,worker,args+i)); }
        for(unsigned i=0;i<4;++i) { CHECK(!pthread_join(threads[i],NULL)); CHECK(!args[i].failed); }
    }
#ifdef QX3_SYSTEM_ORACLE
    printf("SYSTEM ORACLE xxHash %u\n",system_version());
#endif
    printf("PASS %"PRIu64" checks\n",checks); free(buf); return 0;
}
