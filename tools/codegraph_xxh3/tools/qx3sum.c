/* SPDX-License-Identifier: MIT */
#include "qihse_xxh3.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out,"Usage: qx3sum [--backend auto|scalar|sse2|avx2|avx512] [--seed N] [--] [FILE ...]\n"
                "       qx3sum --list | --version\n"
                "No FILE, or FILE '-': read stdin. Seed accepts decimal or 0x hexadecimal.\n");
}
static void print_name(const char *name)
{
    for (const unsigned char *p=(const unsigned char *)name; *p; ++p) {
        if (*p=='\\') fputs("\\\\",stdout);
        else if (*p=='\n') fputs("\\n",stdout);
        else if (*p=='\r') fputs("\\r",stdout);
        else putchar(*p);
    }
}
static int file_hash(qx3_stream *s, uint64_t seed, const char *name)
{
    FILE *in = !strcmp(name,"-") ? stdin : fopen(name,"rb");
    if (!in) { fprintf(stderr,"qx3sum: %s: %s\n",name,strerror(errno)); return 1; }
    if (qx3_stream_reset(s,seed)) {
        perror("qx3sum: reset"); if (in!=stdin) fclose(in); return 1;
    }
    unsigned char buf[65536]; size_t n; int failed=0;
    while ((n=fread(buf,1,sizeof(buf),in))>0) {
        if (qx3_stream_update(s,buf,n)) { perror("qx3sum: update"); failed=1; break; }
    }
    if (ferror(in)) { fprintf(stderr,"qx3sum: %s: read error\n",name); failed=1; }
    if (in!=stdin && fclose(in)) { fprintf(stderr,"qx3sum: %s: close error\n",name); failed=1; }
    if (failed) return 1;
    char hex[33]; qx3_hex(qx3_stream_digest(s),hex);
    if (strpbrk(name,"\\\n\r")) putchar('\\');
    printf("%s  ",hex); print_name(name); putchar('\n');
    return 0;
}
int main(int argc, char **argv)
{
    const char *backend="auto"; uint64_t seed=0; int i=1;
    for (; i<argc; ++i) {
        if (!strcmp(argv[i],"--")) { ++i; break; }
        if (!strcmp(argv[i],"--help")) { usage(stdout); return 0; }
        if (!strcmp(argv[i],"--version")) { puts(qx3_version()); return 0; }
        if (!strcmp(argv[i],"--list")) {
            const char *names[]={"scalar","sse2","avx2","avx512"};
            for (unsigned k=0; k<4; ++k)
                printf("%s: %s\n",names[k],qx3_backend_get(names[k])?"available":"unavailable");
            printf("auto: %s\n",qx3_backend_get("auto")->name); return 0;
        }
        if (!strcmp(argv[i],"--backend")) {
            if (++i==argc) { usage(stderr); return 2; }
            backend=argv[i]; continue;
        }
        if (!strcmp(argv[i],"--seed")) {
            if (++i==argc) { usage(stderr); return 2; }
            char *end=NULL; errno=0;
            int base=(argv[i][0]=='0' && (argv[i][1]=='x' || argv[i][1]=='X')) ? 16 : 10;
            unsigned long long v=strtoull(argv[i],&end,base);
            if (errno || argv[i][0]<'0' || argv[i][0]>'9' || *end || v>UINT64_MAX) {
                fprintf(stderr,"qx3sum: invalid seed\n"); return 2;
            }
            seed=(uint64_t)v; continue;
        }
        if (argv[i][0]=='-' && strcmp(argv[i],"-")) { usage(stderr); return 2; }
        break;
    }
    const qx3_backend *b=qx3_backend_get(backend);
    if (!b) { fprintf(stderr,"qx3sum: backend %s: %s\n",backend,strerror(errno)); return 2; }
    qx3_stream *s=qx3_stream_create(b,seed);
    if (!s) { perror("qx3sum: stream"); return 1; }
    int status=0;
    if (i==argc) status=file_hash(s,seed,"-");
    for (; i<argc; ++i) status |= file_hash(s,seed,argv[i]);
    qx3_stream_free(s);
    if (fflush(stdout) || ferror(stdout)) status=1;
    return status;
}
